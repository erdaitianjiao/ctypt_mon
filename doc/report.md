# dm-crypt 加密磁盘 I/O 性能损失分析报告

## 1. 研究目标

本项目用于分析 Linux `dm-crypt` 加密磁盘相对普通块设备的 I/O 性能损失，重点回答以下问题：

1. 性能损失是否主要来自 AES-XTS 加解密计算；
2. 4 KiB 请求经过 dm-crypt 后是否会被拆成多个底层写请求；
3. 延迟主要发生在 dm-crypt、加密、底层设备还是完成回调阶段；
4. dm-crypt 的 workqueue 调度对低延迟、小块 I/O 有多大影响。

## 2. 测试环境

- 内核：Linux 7.2.0，NixOS；
- CPU：Intel Core i7-13700H；
- 加密算法：`aes-xts-plain64`；
- 当前映射使用 256 bit XTS key（两个 128 bit AES key）；
- Crypto API 实现：`xts-aes-vaes-avx2`，由 `aesni_intel` 提供；
- 加密设备：`dm-crypt -> /dev/loop0 -> 镜像文件`；
- 普通设备：`/dev/loop1 -> 镜像文件`；
- 文件系统：ext4；
- 主要负载：fio，4 KiB 随机读写，direct I/O，QD1，单任务；
- 分析工具：本项目 eBPF 工具、fio、blktrace/blkparse、cryptsetup benchmark。

当前 dm-crypt 默认映射没有启用 `same_cpu_crypt`、`submit_from_crypt_cpus`、
`no_read_workqueue` 或 `no_write_workqueue`：

```text
0 204800 crypt aes-xts-plain64 <key> 0 7:0 0
```

### 2.1 项目组成

项目由观测程序、测试脚本和分析文档三部分组成：

| 文件 | 说明 |
|---|---|
| `src/cryptmon.bpf.c` | eBPF 内核程序。挂载 dm-crypt 和 block 层 kprobe，以 bio 指针关联同一个请求 |
| `src/cryptmon.c` | libbpf 用户态加载器。控制探针 autoload、配置目标设备并输出事件 |
| `src/cryptmon.h` | BPF 与用户态共享的数据结构 |
| `src/vmlinux.h` | 运行内核的 BTF 类型 |
| `src/dm_crypt.h` | dm 模块的私有 BTF 类型 |
| `script/test.sh` | 建立/清理测试设备，运行 fio，并同步采集 cryptmon 与 blktrace |
| `shell.nix` | clang、bpftool、libbpf、fio、blktrace 等可复现工具环境 |
| `Makefile` | 生成 BPF object、libbpf skeleton 和 `cryptmon` 可执行文件 |

### 2.2 测试拓扑

```text
AES 路径：   fio -> ext4 -> dm-crypt(dm-0) -> loop0 -> test/aes.img -> 宿主文件系统
Plain 路径： fio -> ext4 -> loop1                       -> test/plain.img -> 宿主文件系统
```

plain 路径用于测量不经过 dm-crypt 时的基线。AES 路径与 plain 路径分别使用不同镜像，
因此测试应采用多轮和交换顺序的方法降低宿主 writeback 波动，不能依赖单轮结果。

### 2.3 构建和执行

一键执行完整测试：

```bash
./script/run-all.sh
```

该入口自动加载 Nix 环境、构建、建立测试设备、运行 clean fio benchmark、AES
内存 benchmark 和 eBPF/blktrace 采集，并在结束时自动清理。结果保存在
`test/run-<timestamp>/` 及其关联的 `benchmark-*`、`trace-*` 目录。

也可以手动逐步执行：

```bash
nix-shell --run make
sudo env "PATH=$PATH" bash script/test.sh setup
sudo ./cryptmon
sudo env "PATH=$PATH" bash script/test.sh io
sudo env "PATH=$PATH" bash script/test.sh teardown
```

需要 eBPF、fio 与 block trace 联合采集时执行：

```bash
sudo env "PATH=$PATH" bash script/test.sh trace aes randwrite 10
sudo env "PATH=$PATH" bash script/test.sh trace plain randwrite 10
```

采集结果保存在 `test/trace-*`，包括 `cryptmon.log`、`fio.json`、blkparse 文本和 btt 报告。

## 3. eBPF 观测阶段

工具从 `crypt_map()` 开始跟踪一个原始 bio，并记录以下阶段：

- `qcrypt`：进入加/解密处理前的完整间隔，其中还包含 bio/crypto 请求准备，
  不能全部视为 workqueue 睡眠时间；
- `wqwait`：从 `kcryptd_queue_crypt()` 到 `kcryptd_crypt()`，即 crypto workqueue
  精确的排队和唤醒间隔；
- `qsubmit`：进入 dm-crypt 后或加密完成后，到提交底层 clone bio 的间隔；
- `queue`：`qcrypt + qsubmit`；
- `crypto`：从 `crypt_convert()` 到整个 bio 加密或解密完成；
- `device`：从 `dm_submit_bio_remap()` 到 `crypt_endio()`；
- `completion`：最后一个主要阶段完成后，到原始 bio 的 `bio_endio()`；
- `total`：从 `crypt_map()` 到原始 bio 完成。

写请求的主要路径为：

```text
fio
  -> crypt_map
  -> crypto workqueue 排队
  -> AES-XTS 加密
  -> dm-crypt writer 排队
  -> 提交底层 bio
  -> loop/宿主文件系统
  -> 完成回调
```

读请求的主要路径为：

```text
fio
  -> crypt_map
  -> 提交底层读 bio
  -> loop/宿主文件系统完成
  -> crypto workqueue 排队
  -> AES-XTS 解密
  -> 完成原始 bio
```

## 4. 基准性能

在不加载 eBPF 探针的干净测试中，4 KiB、QD1 随机 I/O 结果如下：

| 负载 | 普通设备 | AES dm-crypt | 性能变化 | 平均延迟变化 |
|---|---:|---:|---:|---:|
| 随机读 | 148,995 IOPS | 93,884 IOPS | -37% | 4.943 -> 8.223 us |
| 随机写 | 69,669 IOPS | 34,909 IOPS | -50% | 11.997 -> 25.618 us |

以上结果说明，在当前低延迟 loop 环境中，dm-crypt 对 QD1 小块 I/O 的影响明显，
写路径损失大于读路径。

## 5. AES-XTS 计算性能

使用 `cryptsetup benchmark` 测试纯内存加解密吞吐，三轮中位数如下：

| 算法 | 加密吞吐 | 解密吞吐 | 由吞吐换算的 4 KiB 时间 |
|---|---:|---:|---:|
| AES-XTS-256 | 6953.4 MiB/s | 7019.5 MiB/s | 加密约 0.562 us，解密约 0.557 us |
| AES-XTS-512 | 6583.8 MiB/s | 6612.5 MiB/s | 约 0.594 us |

`cryptsetup benchmark` 是大块连续内存吞吐测试。换算出的 4 KiB 时间表示稳定吞吐下的
AES 数据处理时间，不包括单个 bio 的 Crypto API 初始化、scatterlist、IV、page 和完成处理等固定成本。

eBPF 测得的完整 `crypto` 阶段通常约为 1 至 3 us。这一阶段不只是 AES 指令，
还包含 Crypto API 和 dm-crypt 围绕加密操作的固定处理。因此不能把整个 `crypto`
字段都归因于 AES 算法。

## 6. workqueue A/B 实验

在同一份加密镜像上切换 dm-crypt 参数，使用相同 fio 负载进行三轮测试。写结果中位数如下：

| 配置 | 随机写 IOPS | 平均延迟 | P99 |
|---|---:|---:|---:|
| 普通 loop | 112.1k | 6.87 us | 16.19 us |
| AES 默认 | 60.3k | 14.24 us | 37.63 us |
| AES `no_write_workqueue` | 90.8k | 7.16 us | 16.77 us |
| AES `no_read_workqueue no_write_workqueue` | 89.0k | 7.29 us | 17.79 us |

默认 AES 写相对普通设备增加约 7.37 us。启用 `no_write_workqueue` 后，差距缩小到约
0.29 us，同时写 IOPS 从 60.3k 提升到 90.8k。这是本次实验中证明 workqueue 是主要损失来源的
最直接证据。

读结果中位数如下：

| 配置 | 随机读 IOPS | 平均延迟 |
|---|---:|---:|
| 普通 loop | 127.5k | 5.89 us |
| AES 默认 | 70.1k | 11.25 us |
| AES 关闭读写 workqueue | 96.3k | 8.03 us |

关闭 workqueue 后读延迟仍比普通设备高约 2.15 us。剩余成本包括 AES 解密、Crypto API、
dm bio 克隆和完成处理等。

## 7. 两次写路径调度的直接证据

为了避免长时间逐请求输出造成过大扰动，每种配置固定发送 1000 个 4 KiB、QD1 请求。
eBPF 阶段中位数如下：

| 写阶段 | 默认 | 关闭 workqueue | 减少 |
|---|---:|---:|---:|
| 等待 crypto worker：`wqwait` | 3.521 us | 0.242 us | 3.279 us |
| 加密完成后等待提交：`qsubmit` | 3.024 us | 0.194 us | 2.830 us |
| `crypto` | 2.652 us | 2.615 us | 0.037 us |
| 内部 `queue` 总和 | 8.090 us | 2.229 us | 5.861 us |
| `total` | 24.970 us | 20.262 us | 4.708 us |

切换 workqueue 配置以后，`crypto` 时间基本不变，但两个等待阶段大幅缩短。因此性能改善
不能由 AES 计算速度变化解释，而是来自调度路径变化。

默认写路径包含两个主要的异步交接：

1. 请求进入 dm-crypt 后，被交给 `crypt_queue` 上的 worker 执行加密；
2. 加密完成后，写请求默认还可能交给 dm-crypt writer 线程排序并提交。

在当前测试中，这两次交接的中位数成本合计约 6.5 us，已经明显超过纯 AES-XTS
处理 4 KiB 数据所需的约 0.56 us。

读请求只包含一次主要 crypto worker 等待：

| 读阶段 | 默认 | 关闭 workqueue |
|---|---:|---:|
| `wqwait` | 2.120 us | 0.254 us |
| `crypto` | 2.572 us | 2.731 us |
| `qsubmit` | 1.041 us | 1.003 us |
| `total` | 15.209 us | 13.542 us |

## 8. 请求是否被拆分

blktrace 对 dm 设备和 backing loop 设备的写请求统计如下：

- AES dm 层：244,632 个写请求，99.840% 为 8 sectors，即 4 KiB；
- AES backing loop：244,633 个写请求，99.840% 为 4 KiB；
- dm 与 backing 的请求数量几乎严格为 1:1；
- dispatch 数量与 queue 数量也非常接近，合并比例很低。

因此，在当前 AES-XTS、4 KiB fio 负载下，没有证据表明 dm-crypt 会把一个 4 KiB 写请求
拆成多个底层 bio。AES 测试中观察到的请求数量更少，是 IOPS 降低的结果，不是请求拆分。

## 9. `same_cpu_crypt` 和 `submit_from_crypt_cpus`

实验中单独启用 `same_cpu_crypt` 或 `submit_from_crypt_cpus` 没有获得与
`no_write_workqueue` 相同的稳定收益，在当前 loop 后端上甚至出现明显尾延迟恶化。

这不表示这些选项在真实磁盘上必然有害。loop I/O 最终仍依赖宿主文件系统和其他 worker，
固定 CPU 或改变提交上下文可能引发特殊的 worker 竞争。该结果只能用于说明：当前问题不能简单归结为
“worker 跑到了另一个 CPU”，关键是完整的异步交接和 loop 后端之间的调度关系。

## 10. 最终结论

本次实验得到以下结论：

1. **当前环境中的主要损失不是 AES-XTS 计算。** AES-XTS-256 内存吞吐约 7 GiB/s，
   4 KiB 数据的稳定吞吐时间约 0.56 us。
2. **4 KiB 写请求没有被 dm-crypt 拆分。** dm 层与 backing loop 层的请求大小和数量基本为 1:1。
3. **默认写路径存在两次主要异步调度。** 等待 crypto worker 约 3.5 us，加密后等待 writer
   提交约 3.0 us，二者明显超过纯 AES 时间。
4. **关闭 write workqueue 能显著改善 QD1 小块写。** 写延迟从约 14.24 us 降到 7.16 us，
   IOPS 从约 60.3k 提升到 90.8k。
5. **读路径的主要额外调度发生在底层读取完成后。** 等待 crypto worker 的中位数从
   2.12 us 降到 0.25 us。
6. **剩余成本来自 dm-crypt 固定软件路径。** 包括 Crypto API、IV 和 scatterlist 处理、
   bio 克隆、page 操作以及完成回调。

因此，本测试环境中的加密磁盘性能问题应表述为：

> 在 4 KiB、QD1、极低底层延迟的 loop 测试中，dm-crypt 每个 bio 的固定软件成本和默认异步
> workqueue 调度成本无法被队列并发隐藏，成为主要性能瓶颈；AES-XTS 指令执行只占较小部分。

## 11. 适用范围与限制

当前实验的 backing device 是 loop 镜像文件，不是真实 NVMe。`device` 阶段同时包含：

- loop 驱动处理；
- 宿主文件系统；
- page cache/writeback 行为；
- worker 调度和完成回调。

因此，报告可以确认 dm-crypt workqueue 是当前测试中的主要损失来源，但不能直接把这里测得的微秒数
套用到所有物理磁盘。真实 NVMe 延迟更高、队列深度更大时，固定调度成本可以被并发隐藏，其相对占比
通常会下降；另一方面，高 IOPS NVMe 仍可能暴露 CPU 和 dm-crypt 软件路径瓶颈。

逐请求 eBPF 输出也会增加系统开销，尤其在 `no_*_workqueue` 使处理回到提交线程时更明显。因此：

- 无探针 fio 用于评估总体性能损失；
- 短时间、固定请求数的 eBPF 采样用于判断阶段因果关系；
- blktrace 用于验证请求大小、数量和拆分关系。

三类数据不应被混成同一套绝对性能数字。

## 12. 后续建议

为了验证结论在真实存储设备上的适用性，建议继续进行以下实验：

1. 在独立 NVMe 分区上建立 plain 与 dm-crypt 对照，避免 loop 和宿主文件系统干扰；
2. 分别测试 QD1、QD4、QD16、QD32，观察调度固定成本能否被并发隐藏；
3. 分别测试 4 KiB、16 KiB、64 KiB、128 KiB，观察 AES 吞吐成本随请求大小增长的比例；
4. 将 eBPF 改成内核态直方图/计数聚合，避免逐请求打印影响 fio；
5. 对比默认、`no_read_workqueue`、`no_write_workqueue`，同时记录 CPU 利用率、上下文切换和尾延迟；
6. 在真实设备上重新验证 `same_cpu_crypt`、`submit_from_crypt_cpus` 和 `high_priority`，
   不直接沿用 loop 环境下的结论。

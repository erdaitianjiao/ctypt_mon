# crypt_mon

基于 eBPF 的 dm-crypt I/O 延迟观测工具。通过 kprobe 跟踪 dm-crypt
内核函数，用于辅助分析加密磁盘的 I/O 性能损失。

完整实验过程、数据和结论见 [doc/report.md](doc/report.md)。

## 问题描述

普通 fio 基准只能看到加密设备的 IOPS 和延迟发生变化，无法回答损失具体来自哪里。
本项目把一次 dm-crypt bio 拆成内部等待、AES/Crypto API、底层设备和完成回调阶段，
并结合 plain 设备、dm-crypt 参数 A/B、blktrace 和 AES 内存基准回答以下问题：

- 性能损失主要是 AES 计算，还是 dm-crypt 的调度和 bio 处理；
- 默认 workqueue 对 4 KiB、QD1 请求产生了多少固定开销；
- dm-crypt 是否改变或拆分了底层请求；
- 加密设备与普通设备的底层 I/O 时间是否存在差异。

## 当前结论

在本项目的 NixOS、Intel i7-13700H、loop 镜像、ext4、4 KiB direct I/O、QD1
环境中：

- AES-XTS-256 吞吐约 7 GiB/s，按吞吐换算处理 4 KiB 约需 0.56 us；
- 默认 dm-crypt 写路径等待 crypto worker 的中位数约 3.52 us，加密完成后等待
  writer 提交约 3.02 us；
- 关闭 write workqueue 后，AES 写平均延迟由约 14.24 us 降到 7.16 us；
- blktrace 显示 4 KiB 写在 dm 层和 backing loop 层基本为 1:1，没有被拆成多次写；
- 因此当前环境的主要损失是每 bio 固定软件路径和异步调度，而不是 AES 吞吐不足。

这些微秒数不能直接外推到真实 NVMe。loop 路径还包含宿主文件系统和 writeback worker，
真实设备需要重新进行同样的 A/B 实验。

## 项目结构

| 路径 | 作用 |
|---|---|
| `src/cryptmon.bpf.c` | 内核态 eBPF 探针、bio 状态关联和阶段计时 |
| `src/cryptmon.c` | 加载/附加 BPF 程序并格式化输出事件 |
| `src/cryptmon.h` | 内核态和用户态共享的事件结构与阶段标志 |
| `src/vmlinux.h` | 从运行内核 BTF 生成的基础类型定义 |
| `src/dm_crypt.h` | 从 dm 模块 BTF 生成的 dm-crypt 私有类型定义 |
| `script/test.sh` | 建立 loop/dm-crypt 环境、运行 fio、采集 blktrace |
| `shell.nix` | NixOS 编译和测试依赖 |
| `Makefile` | BPF object、skeleton 和用户态程序的构建规则 |
| `doc/report.md` | 测试环境、实验结果、结论与适用范围 |

生成的 `cryptmon`、`*.o`、镜像文件和 `test/` 测试结果不属于源代码，已由
`.gitignore` 排除。

## 快速开始

### 一键完整测试

推荐从普通用户 shell 直接运行：

```bash
./script/run-all.sh
```

脚本会自动进入 `shell.nix`、编译程序、申请一次 sudo 授权、创建测试设备，随后执行：

1. plain/AES 的 4 KiB QD1 随机读写基准，默认每组 3 秒、3 轮；
2. AES-XTS-256/512 内存 benchmark；
3. AES/plain 随机读写的 eBPF 与 blktrace 联合采集；
4. 环境、dm table、fio JSON、汇总表和报告快照归档；
5. 测试结束或中途失败时自动卸载并清理本次创建的 loop/dm 环境。

常用选项：

```bash
./script/run-all.sh --runtime 10 --rounds 5 --trace-runtime 3
./script/run-all.sh --skip-trace       # 只跑无探针基准和 AES benchmark
./script/run-all.sh --keep-env         # 完成后保留测试挂载和映射
```

结果入口为 `test/run-<timestamp>/`，fio 汇总位于它链接的 benchmark 目录中。
如果发现同名映射或挂载已经存在，一键脚本会拒绝覆盖，需先人工检查后执行
`sudo env "PATH=$PATH" bash script/test.sh teardown`。

### 手动执行

```bash
# 1. 编译
nix-shell --run make

# 2. 建立 256 MiB AES/plain loop 测试环境
sudo env "PATH=$PATH" bash script/test.sh setup

# 3. 在一个终端采集 dm-crypt 阶段
sudo ./cryptmon

# 4. 在另一个终端生成负载
sudo env "PATH=$PATH" bash script/test.sh io

# 5. 或同时采集 eBPF、fio 和 blktrace
sudo env "PATH=$PATH" bash script/test.sh trace aes randwrite 10

# 6. 测试完成后清理挂载、映射和镜像
sudo env "PATH=$PATH" bash script/test.sh teardown
```

`setup` 会创建镜像、loop 设备、dm-crypt 映射和 ext4 文件系统。检测到同名的
`test/aes.img`、`test/plain.img`、挂载或 `crypt_test_aes` 映射时会拒绝覆盖，
需要先检查并显式执行 `teardown`。

## 输出指标

```text
pid=1234 comm=fio op=write bytes=4096 cipher=aes-xts-plain64 qcrypt=2.4 us qsubmit=0.7 us wqwait=1.8 us queue=3.1 us crypto=1.4 us device=6.2 us completion=0.3 us total=11.0 us stages=QKDC
```

- `pid` / `comm`：在 `crypt_map` 中记录的原始 I/O 发起者，而不是
  `crypt_endio` 时的 worker 线程。
- `op` / `bytes`：I/O 方向和请求字节数。
- `qcrypt`：进入加/解密处理前的完整间隔；写位于映射后、加密前，读位于
  底层 I/O 完成后、解密前。它包含准备工作，不能全部解释为睡眠排队。
- `qsubmit`：进入 dm-crypt 后或加密完成后，到提交底层 bio 的间隔。
- `wqwait`：从 `kcryptd_queue_crypt()` 到 `kcryptd_crypt()` 的精确间隔；
  默认模式表示 crypto workqueue 的排队/唤醒时间，inline 模式应接近零。
- `queue`：`qcrypt + qsubmit`，即两段内部等待时间之和。
- `crypto`：从首次进入 `crypt_convert()` 到整个 bio 加/解密完成。
- `device`：从 clone bio 提交到底层 clone bio 完成。
- `completion`：最后一个主动阶段完成后，到原始 bio 完成的收尾耗时。
- `total`：从 `crypt_map` 到原始 bio 的 `bio_endio()`。
- `stages`：`QKDC` 分别表示 queue/crypto/device/completion 均采集完整；
  `-` 表示对应探针没有命中。

写路径的顺序是 `queue -> crypto -> device -> completion`；读路径是
`queue -> device -> crypto -> completion`。完整事件中四个阶段之和应等于 `total`。

要用相同的 eBPF 探针对比 AES backing 设备与 plain 设备的 bio 提交到完成时间：

```bash
sudo ./cryptmon -d /dev/loop0  # AES backing
sudo ./cryptmon -d /dev/loop1  # plain
```

`-d` 模式只加载 `submit_bio_noacct -> bio_endio` 的 device 探针，不加载
dm-crypt 内部探针，保证两个设备的观测开销一致。

## 依赖

- clang / llvm（编译 BPF 程序）
- bpftool（生成 skeleton 头文件）
- libbpf、libelf、zlib（用户态链接）
- gcc、make
- 内核需加载 `dm_crypt` 模块
- fio（I/O 测试，`nix-env -iA nixos.fio`）

## 编译

### Docker 编译（推荐）

项目提供 `Dockerfile`，基于 Debian bookworm，无需本地安装依赖：

```bash
docker build -t cryptmon-build .
docker run --rm -v "$(pwd):/build" cryptmon-build
```

### 本地编译（NixOS）

已有 `shell.nix`，进入 nix shell 后直接 `make`：

```bash
nix-shell
make
```

## 头文件生成

BPF 程序依赖的内核类型头文件通过 `bpftool btf dump` 从运行中的内核 BTF 生成。

### vmlinux.h（全量内核类型）

从 `/sys/kernel/btf/vmlinux` 导出所有内核类型：

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h
```

### dm_crypt 相关类型

dm-crypt 的结构体（`dm_crypt_io`、`crypt_config` 等）定义在内核模块 BTF 中，需额外导出：

```bash
# 导出 dm_mod 模块的类型（dm_per_bio_data 等在此模块）
sudo bpftool btf dump file /sys/kernel/btf/dm_mod \
    -B /sys/kernel/btf/vmlinux format c > src/dm_crypt.h

# 或导出 dm_crypt 模块的类型
sudo bpftool btf dump file /sys/kernel/btf/dm_crypt \
    -B /sys/kernel/btf/vmlinux format c >> src/dm_crypt.h
```

> `-B` 指定基础 BTF（vmlinux），避免重复输出基础类型。

### 关于 dm_per_bio_data

`dm_per_bio_data` 是内核导出函数（`EXPORT_SYMBOL_GPL`），**BPF verifier 不允许调用普通内核函数**（只允许 BPF helper 和 kfunc）。

解决方案：改用 `bio` 指针作为 map key，通过 `io->base_bio` 在各 kprobe 间关联同一个 IO：

- `crypt_map`：直接用传入的 `bio` 指针
- `crypt_convert`/`crypt_endio`：通过 `BPF_CORE_READ(io, base_bio)` 回溯

## 构建流程

`Makefile` 执行三步：

1. `clang` 编译 BPF C 代码 → `src/cryptmon.bpf.o`
2. `bpftool gen skeleton` 生成 skeleton 头文件 → `src/cryptmon.skel.h`
3. `gcc` 编译用户态程序 → `cryptmon`

## 运行测试

`script/test.sh` 提供测试环境搭建和 I/O 负载生成：

```bash
# 搭建测试环境
sudo bash script/test.sh setup

# 生成 I/O 负载
sudo bash script/test.sh io

# 查看状态
sudo bash script/test.sh status

# 清理
sudo bash script/test.sh teardown
```

### eBPF + blktrace 分阶段采集

`trace` 子命令在运行 fio 时同步采集 cryptmon 和 blktrace。AES 测试会同时
跟踪 dm-crypt 设备与它的 backing 设备：

```bash
nix-shell --run make
sudo env "PATH=$PATH" bash script/test.sh trace aes randread 10
sudo env "PATH=$PATH" bash script/test.sh trace plain randread 10
```

每次采集会在 `test/trace-*` 下保存：

- `cryptmon.log`：dm-crypt 内部的 convert 和总路径数据。
- `fio.json`：负载的 IOPS、带宽和延迟数据。
- `dm.txt` / `backing.txt`：block 层 Q/I/D/C 事件。
- `dm-btt.txt` / `backing-btt.txt`：btt 生成的排队、服务和完成时间报告。

`blktrace` 能帮助区分 block queue/device 时间，但不能直接测量 AES 执行时间。
当 backing 设备是 loop 时，结果还包含 loop 和宿主文件系统开销，不等价于裸块设备测试。

测试设备：

| 设备 | 挂载点 | 说明 |
|------|--------|------|
| crypt_test_aes | /mnt/crypt_test/aes | aes-xts-plain64 加密 |
| plain | /mnt/crypt_test/plain | 普通 loop 设备，无 dm-crypt |

## 常见问题

| 问题 | 原因 | 解决 |
|------|------|------|
| `calling kernel function dm_per_bio_data is not allowed` | BPF verifier 不允许调用普通内核函数 | 改用 bio 指针作为 map key，通过 `io->base_bio` 关联 |
| `Failed to bump RLIMIT_MEMLOCK` | BPF 内存限制 | `sudo` 运行或 `ulimit -l unlimited` |
| `libbpf: failed to open BPF object` | skeleton 生成失败 | 检查 bpftool 版本和 BPF 目标文件是否完整 |
| 链接时找不到 `libbpf.so.1.7.0` | libbpf 版本不匹配 | Makefile 中改用 `-lbpf` 自动链接 |
| clang 报 `-fzero-call-used-regs` 错误 | NixOS clang wrapper 注入了不兼容参数 | shell.nix 中用 `llvmPackages.clang-unwrapped` |

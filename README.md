# crypt_mon

基于 eBPF 的 dm-crypt I/O 延迟观测工具。通过 kprobe 跟踪 dm-crypt
内核函数，用于辅助分析加密磁盘的 I/O 性能损失。

## 输出指标

```text
pid=1234 comm=fio op=write bytes=4096 cipher=aes-xts-plain64 convert=12 us calls=1 dm_total=85 us
```

- `pid` / `comm`：在 `crypt_map` 中记录的原始 I/O 发起者，而不是
  `crypt_endio` 时的 worker 线程。
- `op` / `bytes`：I/O 方向和请求字节数。
- `convert`：一个 bio 相关的 `crypt_convert()` 函数调用累计耗时。
- `calls`：累计的 `crypt_convert()` 调用次数。
- `dm_total`：从 `crypt_map` 到 `crypt_endio` 的 dm-crypt 路径总耗时。

> `convert` 是函数调用的墙钟时间，异步加密可能在函数返回后继续；
> `dm_total` 则包含底层设备 I/O 和排队时间。两者都不应单独解释为
> “AES 计算耗时”。评估整体性能损失时，仍应以相同 fio 负载下的
> plain/dm-crypt 对照数据为主。

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

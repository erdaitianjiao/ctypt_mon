// #include "vmlinux.h"
#include "dm_crypt.h"
#include "cryptmon.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 时间戳存储结构
struct io_timestamps {
    u64 crypt_map_time;      // crypt_map时间
    u64 crypt_start_time;    // crypt_convert开始时间
    u64 crypt_end_time;      // crypt_convert结束时间
    u64 total_start_time;    // 总开始时间（用于计算total_time_ns）
};

// BPF Maps - 使用bio指针作为key，避免调用dm_per_bio_data
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct bio *);
    __type(value, struct io_timestamps);
} io_timestamps_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// 进入加密层 - 直接用bio作为key，不需要dm_per_bio_data
SEC("kprobe/crypt_map")
int BPF_KPROBE(crypt_map, struct dm_target *ti, struct bio *bio)
{	
	u64 ts = bpf_ktime_get_ns();
	
	// 初始化时间戳结构，以bio为key
	struct io_timestamps timestamps = {};
	timestamps.crypt_map_time = ts;
	timestamps.total_start_time = ts;
	
	// 存储到map中
	bpf_map_update_elem(&io_timestamps_map, &bio, &timestamps, BPF_ANY);
	
	return 0;
}

// 加密处理函数 - 通过io->base_bio回溯到原始bio作为key
SEC("kprobe/crypt_convert")
int BPF_KPROBE(crypt_convert_entry, struct crypt_config *cc, struct convert_context *dm_ctx)
{	
	// 获取 io 指针：io = ctx - offsetof(struct dm_crypt_io, ctx)
	size_t offset = bpf_core_field_offset(struct dm_crypt_io, ctx);
	struct dm_crypt_io *io = (void *)((char *)dm_ctx - offset);
	if (!io) {
		return 0;
	}

	// 通过base_bio回溯到原始bio
	struct bio *bio = BPF_CORE_READ(io, base_bio);
	if (!bio) {
		return 0;
	}

	u64 ts = bpf_ktime_get_ns();
	
	// 从map中获取或创建时间戳结构
	struct io_timestamps *timestamps = bpf_map_lookup_elem(&io_timestamps_map, &bio);
	if (timestamps) {
		timestamps->crypt_start_time = ts;
		if (timestamps->total_start_time == 0) {
			timestamps->total_start_time = ts;
		}
		bpf_map_update_elem(&io_timestamps_map, &bio, timestamps, BPF_ANY);
	} else {
		struct io_timestamps new_ts = {};
		new_ts.crypt_start_time = ts;
		new_ts.total_start_time = ts;
		bpf_map_update_elem(&io_timestamps_map, &bio, &new_ts, BPF_ANY);
	}
	
	return 0;
}

SEC("kretprobe/crypt_convert")
int BPF_KRETPROBE(ctypy_convert_exit, int ret)
{
	// 从kretprobe中获取参数需要使用BPF_CORE_READ
	// 但这里我们无法直接获取io指针，所以加密结束时间在crypt_endio中记录
	// 为了更准确，我们可以尝试从pt_regs中获取参数
	// 但为了简化，加密时间将在crypt_endio中计算
	return 0;
}

SEC("kprobe/crypt_endio")
int BPF_KPROBE(crypt_endio, struct bio *clone)
{
	// 在 dm-crypt 中，clone->bi_private 永远指向 dm_crypt_io
	struct dm_crypt_io *io = (void *)BPF_CORE_READ(clone, bi_private);
	if (!io) {
		return 0;
	}

	// 通过base_bio回溯到原始bio
	struct bio *bio = BPF_CORE_READ(io, base_bio);
	if (!bio) {
		return 0;
	}

	u64 end_time = bpf_ktime_get_ns();
	
	// 从map中获取时间戳
	struct io_timestamps *timestamps = bpf_map_lookup_elem(&io_timestamps_map, &bio);
	if (!timestamps) {
		return 0;
	}
	
	// 计算加密时间和总时间
	u64 crypt_time_ns = 0;
	u64 total_time_ns = 0;
	
	if (timestamps->crypt_start_time > 0) {
		crypt_time_ns = end_time - timestamps->crypt_start_time;
	}
	
	if (timestamps->total_start_time > 0) {
		total_time_ns = end_time - timestamps->total_start_time;
	}
	
	// 获取进程信息
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	
	// 获取进程名和加密算法
	struct event evt = {};
	evt.pid = pid;
	bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
	evt.crypt_time_ns = crypt_time_ns;
	evt.total_time_ns = total_time_ns;
	
	// 获取加密算法名称
	struct crypt_config *cc = BPF_CORE_READ(io, cc);
	if (cc) {
		char *cipher_string = BPF_CORE_READ(cc, cipher_string);
		if (cipher_string) {
			bpf_probe_read_kernel_str(&evt.cipher, sizeof(evt.cipher), cipher_string);
		}
	}
	
	// 发送事件到用户空间
	u32 cpu = bpf_get_smp_processor_id();
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	
	// 清理map条目
	bpf_map_delete_elem(&io_timestamps_map, &bio);
	
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

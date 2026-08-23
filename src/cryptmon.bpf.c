// #include "vmlinux.h"
#include "dm_crypt.h"
#include "cryptmon.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 时间戳存储结构
struct io_timestamps {
    u64 total_start_time;
    u64 convert_time_ns;
    u32 pid;
    u32 bytes;
    u32 op;
    u32 convert_calls;
    char comm[16];
};

struct active_convert {
    struct bio *bio;
    u64 start_time;
};

// BPF Maps - 使用bio指针作为key，避免调用dm_per_bio_data
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct bio *);
    __type(value, struct io_timestamps);
} io_timestamps_map SEC(".maps");

// crypt_convert 的返回探针拿不到入参，按执行线程保存当前调用。
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct active_convert);
} active_convert_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// 进入加密层 - 直接用bio作为key，不需要dm_per_bio_data
SEC("kprobe/crypt_map")
int BPF_KPROBE(crypt_map, struct dm_target *ti, struct bio *bio)
{
	(void)ctx;
	(void)ti;
	u64 ts = bpf_ktime_get_ns();
	
	struct io_timestamps timestamps = {};
	timestamps.total_start_time = ts;
	timestamps.pid = bpf_get_current_pid_tgid() >> 32;
	timestamps.bytes = BPF_CORE_READ(bio, bi_iter.bi_size);
	timestamps.op = BPF_CORE_READ(bio, bi_opf) & 0xff;
	bpf_get_current_comm(&timestamps.comm, sizeof(timestamps.comm));
	
	// 存储到map中
	bpf_map_update_elem(&io_timestamps_map, &bio, &timestamps, BPF_ANY);
	
	return 0;
}

// 加密处理函数 - 通过io->base_bio回溯到原始bio作为key
SEC("kprobe/crypt_convert")
int BPF_KPROBE(crypt_convert_entry, struct crypt_config *cc, struct convert_context *dm_ctx)
{
	(void)ctx;
	(void)cc;
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

	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct active_convert active = {
		.bio = bio,
		.start_time = bpf_ktime_get_ns(),
	};
	bpf_map_update_elem(&active_convert_map, &pid_tgid, &active, BPF_ANY);
	
	return 0;
}

SEC("kretprobe/crypt_convert")
int BPF_KRETPROBE(crypt_convert_exit, int ret)
{
	(void)ctx;
	(void)ret;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct active_convert *active;
	struct io_timestamps *timestamps;

	active = bpf_map_lookup_elem(&active_convert_map, &pid_tgid);
	if (!active)
		return 0;

	timestamps = bpf_map_lookup_elem(&io_timestamps_map, &active->bio);
	if (timestamps) {
		__sync_fetch_and_add(&timestamps->convert_time_ns,
				     bpf_ktime_get_ns() - active->start_time);
		__sync_fetch_and_add(&timestamps->convert_calls, 1);
	}
	bpf_map_delete_elem(&active_convert_map, &pid_tgid);
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
	
	// 请求发起者在 crypt_map 中保存，endio 往往运行在 worker 上下文。
	struct event evt = {};
	evt.pid = timestamps->pid;
	evt.op = timestamps->op;
	evt.bytes = timestamps->bytes;
	evt.convert_calls = timestamps->convert_calls;
	__builtin_memcpy(evt.comm, timestamps->comm, sizeof(evt.comm));
	evt.convert_time_ns = timestamps->convert_time_ns;
	evt.dm_total_time_ns = end_time - timestamps->total_start_time;
	
	// 获取加密算法名称
	struct crypt_config *cc = BPF_CORE_READ(io, cc);
	if (cc) {
		char *cipher_string = BPF_CORE_READ(cc, cipher_string);
		if (cipher_string) {
			bpf_probe_read_kernel_str(&evt.cipher, sizeof(evt.cipher), cipher_string);
		}
	}
	
	// 发送事件到用户空间
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	
	// 清理map条目
	bpf_map_delete_elem(&io_timestamps_map, &bio);
	
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

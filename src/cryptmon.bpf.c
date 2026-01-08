// #include "vmlinux.h"
#include "dm_crypt.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


// 总体信息，包括加密层和
struct crypt_io_info {
	u64 base_bio_ptr;      		// 原始 BIO 地址
    u32 sector;            		// 起始扇区
    u32 len;               		// IO 长度
	char cipher_name[32];		// 加密函数名称

	u64 crypt_map_time;			// 进入dm_crypt
	u64 crypt_start;			// 进入加密时间
	u64 crypt_end;				// 加密结束时间

    u64 pure_crypt_time;        // 纯粹的cpu加密时间
	int crypt_convert_calls;	// 调用次数
};

// struct bio 和 struct io_info的哈希表 通过bio来定位io_info
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__uint(key_size, sizeof(void *));
	__uint(value_size, sizeof(struct crypt_io_info));
} io_map SEC(".maps");

// 用tid来定位加密计算 负责计算纯净加密时间
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(void *));
} tid_ptr SEC(".maps");

// ringbuffer
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 进入加密层
SEC("kprobe/dm_crypt_queue_io")
int BPF_KPROBE(dm_crypt_queue_io, struct dm_crypt_io *io)
{
	void *io_ptr = (void *)io;
	struct crypt_io_info info;

	info.base_bio_ptr = (u64)BPF_CORE_READ(io, base_bio);
	info.sector = BPF_CORE_READ(io, sector);
	info.crypt_map_time = bpf_ktime_get_ns();

	// 获取算法名称
	struct crypt_config *cc = BPF_CORE_READ(io, cc);
	BPF_CORE_READ_STR_INTO(info.cipher_name, cc, cipher_string);

	bpf_map_update_elem(&io_map, &io_ptr, &info, BPF_ANY);
	return 0;
}

SEC("kprobe/crypt_convert")
int BPF_KPROBE(crypt_convert_entery, struct crypt_config *cc, struct convert_context *dm_ctx)
{	
	u64 tid = bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();

	size_t offset = bpf_core_field_offset(struct dm_crypt_io, ctx);
	struct dm_crypt_io *io = (void *)((char *)ctx - offset);

	

	return 0;


}

SEC("kretprobe/crypt_convert")
int BPF_KRETPROBE(ctypy_convert_exit)
{
	return 0;
}



char LICENSE[] SEC("license") = "GPL";

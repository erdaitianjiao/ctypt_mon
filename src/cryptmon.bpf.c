// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>
// #include "cryptmon.h"

// struct io_info {
// 	u64 start_ts;
// 	u64 crypt_start;
// 	u64 crypt_duration;
// 	u32 pid;
// 	char comm[16];
// 	char cipher[32];
// };

// struct {
	
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 10240);
// 	__type(key, u64);
// 	__type(value, struct io_info);

// } tracker SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 1024);
// 	__type(key, 32);
// 	__type(value, u64);
// } in_flight SEC(".maps");

// // 用于给用户发送的buffer
// struct {
// 	__uint(type, BPF_MAP_TYPE_RINGBUF);
// 	__uint(max_entries, 256 * 1024);


// } rb SEC(".maps");

// static __always_inline void get_cipher_name(struct convert_context *ctx, char *dest)
// {
// 	struct crypt_config *cc = BPF_CORE_READ(ctx, cc);
// 	if (cc) {
// 		BPF_CORE_READ_STR_INTO(dest, cc, cipher_string);
// 	}
// }

// SEC("kprobe/crypt_convert")
// int BPF_KPROBE(crypt_convert_enteri, struct pt_regs *regs)
// {	
// 	struct convert_context *cc_ctx = (struct convert_context *) PT_REGS_PARM1(ctx); 
	
// 	u64 bio_ptr = (u64)BPF_CORE_READ(cc_ctx, bio_in);
// 	if (!bio_ptr) return 0;
	
// 	struct io_info info = {};
// 	info.crypt_start = bpf_ktime_get_ns();
// 	info.pid = bpf_get_current_pid_tgid() >> 32;
// 	bpf_get_current_comm(&info.comm, sizeof(info.comm));

// 	// 提取算法名称
// 	get_cipher_name(ctx, info.cipher);
// 	bpf_map_update_elem(&tracker, &bio_ptr, &info, BPF_ANY);
//     return 0;
// }

// SEC("kretprobe/crypt_convert")
// int BPF_KRETPROBE(crypt_convert_exit)
// {
// 	u32 pid = bpf_get_current_pid_tgid() >> 32;

// 	u64 *bio_ptr_ptr = bpf_map_lookup_elem(&in_flight, &pid);
// 	if (!bio_ptr_ptr) return 0;

// 	u64 bio_ptr = *bio_ptr_ptr;

// 	struct io_info *info = bpf_map_lookup_elem(&tracker, &bio_ptr);
// 	if (info) {
// 		info->crypt_duration = bpf_ktime_get_ns() - info->crypt_start;
// 	}
	
// 	bpf_map_delete_elem(&in_flight, &pid);
// 	return 0;

// }

// SEC("kprobe/bio_endio")
// int BPF_KPROBE(bio_endio, struct bio *bio)
// {
// 	u64 bio_ptr = (u64)bio;
// 	struct io_info *info = bpf_map_lookup_elem(&tracker, &bio_ptr);
// 	if (!info) return 0;
// 	u64 end_ns = bpf_ktime_get_ns();
// 	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
// 	if (e) {
// 		e->pid = info->pid;
// 		e->total_time_ns = end_ns - info->start_ts;
// 		e->crypt_time_ns = info->crypt_duration;

// 		bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), info->comm);
// 		bpf_probe_read_kernel_str(&e->cipher, sizeof(e->cipher), info->cipher);

// 		bpf_ringbuf_submit(e, 0);

// 	}
// 	bpf_map_delete_elem(&tracker, &bio_ptr);

// }

// char LICENSE[] SEC("license") = "GPL";

// #include "vmlinux.h"
#include "dm_crypt_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cryptmon.h"


struct io_info {
    u64 start_ts;
    u64 crypt_start;
    u64 crypt_duration;
    u32 pid;
    char comm[16];
    char cipher[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);   // bio 指针
    __type(value, struct io_info);
} tracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);   // 错误 1 修复: 这里应该是 u32 类型，代表 PID
    __type(value, u64); // bio 指针
} in_flight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline void get_cipher_name(struct convert_context *ctx, char *dest)
{   
    struct crypt_config_local *cc;
    bpf_probe_read_kernel(&cc, sizeof(cc), ctx + 8);

    if (cc) {
        char *name_ptr;
        // 假设 cipher_string 在 crypt_config 偏移 0 的位置
        bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), (void *)cc);
        if (name_ptr) {
            bpf_probe_read_kernel_str(dest, 32, name_ptr);
        }
    }   
}

SEC("kprobe/crypt_convert")
int BPF_KPROBE(crypt_convert_enteri, struct convert_context *cc_ctx)
{   

    u64 bio_ptr = (u64)BPF_CORE_READ(cc_ctx, bio_in);
    if (!bio_ptr) return 0;
    
    struct io_info info = {};
    info.crypt_start = bpf_ktime_get_ns();
    info.start_ts = info.crypt_start; // 错误 3 修复: 别忘了给 start_ts 赋值，否则后面计算 total 会出错
    info.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    // 错误 4 修复: 应该传入 cc_ctx 指针，而不是 regs
    get_cipher_name(cc_ctx, info.cipher);
    
    bpf_map_update_elem(&tracker, &bio_ptr, &info, BPF_ANY);
    
    // 错误 5 修复: 必须在这里更新 in_flight，否则 kretprobe 找不到对应的 bio
    u32 pid = info.pid;
    bpf_map_update_elem(&in_flight, &pid, &bio_ptr, BPF_ANY);
    
    return 0;
}

SEC("kretprobe/crypt_convert")
int BPF_KRETPROBE(crypt_convert_exit)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u64 *bio_ptr_ptr = bpf_map_lookup_elem(&in_flight, &pid);
    if (!bio_ptr_ptr) return 0;

    u64 bio_ptr = *bio_ptr_ptr;

    struct io_info *info = bpf_map_lookup_elem(&tracker, &bio_ptr);
    if (info) {
        info->crypt_duration = bpf_ktime_get_ns() - info->crypt_start;
    }
    
    bpf_map_delete_elem(&in_flight, &pid);
    return 0;
}

SEC("kprobe/bio_endio")
int BPF_KPROBE(bio_endio, struct bio *bio)
{
    u64 bio_ptr = (u64)bio;
    struct io_info *info = bpf_map_lookup_elem(&tracker, &bio_ptr);
    if (!info) return 0;

    u64 end_ns = bpf_ktime_get_ns();
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->pid = info->pid;
        e->total_time_ns = end_ns - info->start_ts;
        e->crypt_time_ns = info->crypt_duration;

        bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), info->comm);
        bpf_probe_read_kernel_str(&e->cipher, sizeof(e->cipher), info->cipher);

        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&tracker, &bio_ptr);
    return 0; // 错误 6 修复: 加上 return
}

char LICENSE[] SEC("license") = "GPL";

// #include "vmlinux.h"
#include "dm_crypt.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 进入加密层
SEC("kprobe/crypt_map")
int BPF_KPROBE(crypt_map, struct dm_target *ti, struct bio *bio)
{
	bpf_printk(">>> crypt_map: bio=%p\n", bio);
	return 0;
}

// 加密处理函数
SEC("kprobe/crypt_convert")
int BPF_KPROBE(crypt_convert_entry, struct crypt_config *cc, struct convert_context *dm_ctx)
{	
	// 获取 io 指针：io = ctx - offsetof(struct dm_crypt_io, ctx)
	size_t offset = bpf_core_field_offset(struct dm_crypt_io, ctx);
	struct dm_crypt_io *io = (void *)((char *)dm_ctx - offset);

	// 尝试读取 base_bio
	struct bio *base_bio = NULL;
	bpf_probe_read_kernel(&base_bio, sizeof(base_bio), &io->base_bio);

	bpf_printk("=== crypt_convert_entry: io=%p, base_bio=%p\n", io, base_bio);
	return 0;

}

SEC("kretprobe/crypt_convert")
int BPF_KRETPROBE(ctypy_convert_exit)
{

	return 0;
}

SEC("kprobe/crypt_endio")
int BPF_KPROBE(crypt_endio, struct bio *clone)
{

	// 在 dm-crypt 中，clone->bi_private 永远指向 dm_crypt_io
	struct dm_crypt_io *io = (void *)BPF_CORE_READ(clone, bi_private);

	if (io) {
		struct bio *base_bio = BPF_CORE_READ(io, base_bio);
		bpf_printk("<<< crypt_endio: clone=%p, io=%p, base_bio=%p\n", clone, io, base_bio);
	}
	return 0;
}


char LICENSE[] SEC("license") = "GPL";

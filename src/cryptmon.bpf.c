#include "dm_crypt.h"
#include "cryptmon.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct io_state {
	u64 map_time;
	u64 crypto_start_time;
	u64 crypto_end_time;
	u64 crypto_queued_time;
	u64 crypto_worker_time;
	u64 device_start_time;
	u64 device_end_time;
	u32 pid;
	u32 bytes;
	u32 op;
	char comm[16];
	char cipher[32];
};

struct block_io_state {
	u64 start_time;
	u32 pid;
	u32 bytes;
	u32 op;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct bio *);
	__type(value, struct io_state);
} io_state_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct bio *);
	__type(value, struct block_io_state);
} block_io_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct device_filter);
} device_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline struct bio *base_bio_from_ctx(struct convert_context *dm_ctx)
{
	size_t offset = bpf_core_field_offset(struct dm_crypt_io, ctx);
	struct dm_crypt_io *io = (void *)((char *)dm_ctx - offset);

	if (!io)
		return NULL;
	return BPF_CORE_READ(io, base_bio);
}

static __always_inline struct dm_crypt_io *crypt_io_from_work(struct work_struct *work)
{
	size_t offset = bpf_core_field_offset(struct dm_crypt_io, work);

	return (void *)((char *)work - offset);
}

static __always_inline void mark_crypto_done(struct dm_crypt_io *io)
{
	struct bio *bio;
	struct io_state *state;

	if (!io)
		return;
	bio = BPF_CORE_READ(io, base_bio);
	if (!bio)
		return;
	state = bpf_map_lookup_elem(&io_state_map, &bio);
	if (state && !state->crypto_end_time)
		state->crypto_end_time = bpf_ktime_get_ns();
}

SEC("kprobe/crypt_map")
int BPF_KPROBE(crypt_map, struct dm_target *ti, struct bio *bio)
{
	struct crypt_config *cc;
	struct io_state state = {};

	(void)ctx;
	state.map_time = bpf_ktime_get_ns();
	state.pid = bpf_get_current_pid_tgid() >> 32;
	state.bytes = BPF_CORE_READ(bio, bi_iter.bi_size);
	state.op = BPF_CORE_READ(bio, bi_opf) & 0xff;
	/* dm-crypt bypasses zero-length preflushes and non-data operations. */
	if (!state.bytes || state.op > 1)
		return 0;
	bpf_get_current_comm(&state.comm, sizeof(state.comm));

	cc = (struct crypt_config *)BPF_CORE_READ(ti, private);
	if (cc) {
		char *cipher = BPF_CORE_READ(cc, cipher_string);

		if (cipher)
			bpf_probe_read_kernel_str(&state.cipher, sizeof(state.cipher), cipher);
	}
	bpf_map_update_elem(&io_state_map, &bio, &state, BPF_ANY);
	return 0;
}

SEC("kprobe/crypt_convert")
int BPF_KPROBE(crypt_convert_entry, struct crypt_config *cc,
	       struct convert_context *dm_ctx)
{
	struct bio *bio;
	struct io_state *state;

	(void)ctx;
	(void)cc;
	bio = base_bio_from_ctx(dm_ctx);
	if (!bio)
		return 0;
	state = bpf_map_lookup_elem(&io_state_map, &bio);
	if (state && !state->crypto_start_time)
		state->crypto_start_time = bpf_ktime_get_ns();
	return 0;
}

SEC("kprobe/kcryptd_queue_crypt")
int BPF_KPROBE(crypt_work_queued, struct dm_crypt_io *io)
{
	struct bio *bio;
	struct io_state *state;

	(void)ctx;
	if (!io)
		return 0;
	bio = BPF_CORE_READ(io, base_bio);
	if (!bio)
		return 0;
	state = bpf_map_lookup_elem(&io_state_map, &bio);
	if (state)
		state->crypto_queued_time = bpf_ktime_get_ns();
	return 0;
}

SEC("kprobe/kcryptd_crypt")
int BPF_KPROBE(crypt_worker_started, struct work_struct *work)
{
	struct dm_crypt_io *io;
	struct bio *bio;
	struct io_state *state;

	(void)ctx;
	if (!work)
		return 0;
	io = crypt_io_from_work(work);
	bio = BPF_CORE_READ(io, base_bio);
	if (!bio)
		return 0;
	state = bpf_map_lookup_elem(&io_state_map, &bio);
	if (state && state->crypto_queued_time)
		state->crypto_worker_time = bpf_ktime_get_ns();
	return 0;
}

SEC("kprobe/kcryptd_crypt_write_io_submit")
int BPF_KPROBE(crypt_write_crypto_done, struct dm_crypt_io *io, int async)
{
	(void)ctx;
	(void)async;
	mark_crypto_done(io);
	return 0;
}

SEC("kprobe/kcryptd_crypt_read_done")
int BPF_KPROBE(crypt_read_crypto_done, struct dm_crypt_io *io)
{
	(void)ctx;
	mark_crypto_done(io);
	return 0;
}

SEC("kprobe/dm_submit_bio_remap")
int BPF_KPROBE(crypt_device_submit, struct bio *base_bio, struct bio *clone)
{
	struct io_state *state;

	(void)ctx;
	(void)clone;
	state = bpf_map_lookup_elem(&io_state_map, &base_bio);
	if (state && !state->device_start_time)
		state->device_start_time = bpf_ktime_get_ns();
	return 0;
}

SEC("kprobe/crypt_endio")
int BPF_KPROBE(crypt_device_done, struct bio *clone)
{
	struct dm_crypt_io *io;
	struct bio *bio;
	struct io_state *state;

	(void)ctx;
	io = (void *)BPF_CORE_READ(clone, bi_private);
	if (!io)
		return 0;
	bio = BPF_CORE_READ(io, base_bio);
	if (!bio)
		return 0;
	state = bpf_map_lookup_elem(&io_state_map, &bio);
	if (state && !state->device_end_time)
		state->device_end_time = bpf_ktime_get_ns();
	return 0;
}

/* Measure the same submit-to-endio interval for a selected plain block device. */
SEC("kprobe/submit_bio_noacct")
int BPF_KPROBE(block_device_submit, struct bio *bio)
{
	u32 key = 0;
	struct device_filter *filter;
	struct block_device *bdev;
	dev_t dev;
	u32 dev_major;
	u32 dev_minor;
	struct block_io_state state = {};

	(void)ctx;
	filter = bpf_map_lookup_elem(&device_config, &key);
	if (!filter || (!filter->major && !filter->minor))
		return 0;
	bdev = BPF_CORE_READ(bio, bi_bdev);
	if (!bdev)
		return 0;
	dev = BPF_CORE_READ(bdev, bd_dev);
	dev_major = dev >> 20;
	dev_minor = dev & ((1U << 20) - 1);
	if (dev_major != filter->major || dev_minor != filter->minor)
		return 0;

	state.start_time = bpf_ktime_get_ns();
	state.pid = bpf_get_current_pid_tgid() >> 32;
	state.bytes = BPF_CORE_READ(bio, bi_iter.bi_size);
	state.op = BPF_CORE_READ(bio, bi_opf) & 0xff;
	if (!state.bytes || state.op > 1)
		return 0;
	bpf_get_current_comm(&state.comm, sizeof(state.comm));
	bpf_map_update_elem(&block_io_map, &bio, &state, BPF_ANY);
	return 0;
}

static __always_inline void emit_block_device_event(void *ctx, struct bio *bio,
						     u64 end_time)
{
	u32 key = 0;
	struct device_filter *filter;
	struct block_io_state *state;
	struct event evt = {};

	state = bpf_map_lookup_elem(&block_io_map, &bio);
	if (!state)
		return;
	filter = bpf_map_lookup_elem(&device_config, &key);
	if (!filter)
		return;

	evt.type = CRYPTMON_EVENT_BLOCK;
	evt.pid = state->pid;
	evt.op = state->op;
	evt.bytes = state->bytes;
	evt.dev_major = filter->major;
	evt.dev_minor = filter->minor;
	evt.device_time_ns = end_time - state->start_time;
	evt.total_time_ns = evt.device_time_ns;
	evt.stage_mask = CRYPTMON_STAGE_DEVICE;
	__builtin_memcpy(evt.comm, state->comm, sizeof(evt.comm));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	bpf_map_delete_elem(&block_io_map, &bio);
}

SEC("kprobe/bio_endio")
int BPF_KPROBE(crypt_request_done, struct bio *bio)
{
	struct io_state *state;
	struct event evt = {};
	u64 end_time = bpf_ktime_get_ns();
	u64 queue_ns = 0;
	u32 queue_valid = 0;

	emit_block_device_event(ctx, bio, end_time);
	state = bpf_map_lookup_elem(&io_state_map, &bio);
	if (!state)
		return 0;

	evt.type = CRYPTMON_EVENT_DM;
	evt.pid = state->pid;
	evt.op = state->op;
	evt.bytes = state->bytes;
	__builtin_memcpy(evt.comm, state->comm, sizeof(evt.comm));
	__builtin_memcpy(evt.cipher, state->cipher, sizeof(evt.cipher));

	if (state->crypto_start_time && state->crypto_end_time &&
	    state->crypto_end_time >= state->crypto_start_time) {
		evt.crypto_time_ns = state->crypto_end_time - state->crypto_start_time;
		evt.stage_mask |= CRYPTMON_STAGE_CRYPTO;
	}
	if (state->crypto_queued_time && state->crypto_worker_time &&
	    state->crypto_worker_time >= state->crypto_queued_time)
		evt.workqueue_time_ns = state->crypto_worker_time -
					state->crypto_queued_time;
	if (state->device_start_time && state->device_end_time &&
	    state->device_end_time >= state->device_start_time) {
		evt.device_time_ns = state->device_end_time - state->device_start_time;
		evt.stage_mask |= CRYPTMON_STAGE_DEVICE;
	}

	if (state->op == 0) {
		if (state->device_start_time >= state->map_time &&
		    state->crypto_start_time >= state->device_end_time) {
			evt.submit_queue_time_ns =
				state->device_start_time - state->map_time;
			evt.crypto_queue_time_ns =
				state->crypto_start_time - state->device_end_time;
			queue_ns = evt.submit_queue_time_ns +
				   evt.crypto_queue_time_ns;
			queue_valid = 1;
		}
		if (state->crypto_end_time && end_time >= state->crypto_end_time) {
			evt.completion_time_ns = end_time - state->crypto_end_time;
			evt.stage_mask |= CRYPTMON_STAGE_COMPLETION;
		}
	} else {
		if (state->crypto_start_time >= state->map_time &&
		    state->device_start_time >= state->crypto_end_time) {
			evt.crypto_queue_time_ns =
				state->crypto_start_time - state->map_time;
			evt.submit_queue_time_ns =
				state->device_start_time - state->crypto_end_time;
			queue_ns = evt.crypto_queue_time_ns +
				   evt.submit_queue_time_ns;
			queue_valid = 1;
		}
		if (state->device_end_time && end_time >= state->device_end_time) {
			evt.completion_time_ns = end_time - state->device_end_time;
			evt.stage_mask |= CRYPTMON_STAGE_COMPLETION;
		}
	}
	evt.queue_time_ns = queue_ns;
	evt.total_time_ns = end_time - state->map_time;
	if (queue_valid)
		evt.stage_mask |= CRYPTMON_STAGE_QUEUE;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	bpf_map_delete_elem(&io_state_map, &bio);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

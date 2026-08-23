#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "cryptmon.h"
#include "cryptmon.skel.h"

static volatile sig_atomic_t stop = 0;
void sig_handler(int sig) {
    (void)sig;
    stop = 1;
}

static const char *op_name(unsigned int op) {
    switch (op) {
    case 0: return "read";
    case 1: return "write";
    case 2: return "flush";
    case 3: return "discard";
    default: return "other";
    }
}

static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
    const struct event *e = data;
    (void)ctx;
    (void)cpu;
    if (data_sz < sizeof(*e))
        return;
    if (e->type == CRYPTMON_EVENT_BLOCK) {
        printf("type=device dev=%u:%u pid=%-8u comm=%-16s op=%-7s "
               "bytes=%-8u device=%9.3f us\n",
               e->dev_major, e->dev_minor, e->pid, e->comm,
               op_name(e->op), e->bytes, e->device_time_ns / 1000.0);
        return;
    }
    printf("pid=%-8u comm=%-16s op=%-7s bytes=%-8u cipher=%-16s "
           "qcrypt=%9.3f us qsubmit=%9.3f us wqwait=%9.3f us queue=%9.3f us "
           "crypto=%9.3f us device=%9.3f us "
           "completion=%9.3f us total=%9.3f us stages=%c%c%c%c\n",
           e->pid, e->comm, op_name(e->op), e->bytes, e->cipher,
           e->crypto_queue_time_ns / 1000.0,
           e->submit_queue_time_ns / 1000.0,
           e->workqueue_time_ns / 1000.0,
           e->queue_time_ns / 1000.0, e->crypto_time_ns / 1000.0,
           e->device_time_ns / 1000.0, e->completion_time_ns / 1000.0,
           e->total_time_ns / 1000.0,
           e->stage_mask & CRYPTMON_STAGE_QUEUE ? 'Q' : '-',
           e->stage_mask & CRYPTMON_STAGE_CRYPTO ? 'K' : '-',
           e->stage_mask & CRYPTMON_STAGE_DEVICE ? 'D' : '-',
           e->stage_mask & CRYPTMON_STAGE_COMPLETION ? 'C' : '-');
}

static void handle_lost_events(void *ctx, int cpu, unsigned long long count) {
    (void)ctx;
    fprintf(stderr, "Lost %llu events on CPU %d\n", count, cpu);
}

int main(int argc, char **argv) {
    struct cryptmon_bpf *skel;
    struct perf_buffer *pb;
    struct device_filter filter = {};
    struct stat st;
    unsigned int config_key = 0;
    int err = 0;

    if (argc == 3 && strcmp(argv[1], "-d") == 0) {
        if (stat(argv[2], &st) || !S_ISBLK(st.st_mode)) {
            fprintf(stderr, "Not a block device: %s\n", argv[2]);
            return 1;
        }
        filter.major = major(st.st_rdev);
        filter.minor = minor(st.st_rdev);
    } else if (argc != 1) {
        fprintf(stderr, "Usage: %s [-d block-device]\n", argv[0]);
        return 1;
    }

    printf("crypt_mon is running... (Ctrl+C to stop)\n");
    signal(SIGINT, sig_handler);

    skel = cryptmon_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program\n");
        return 1;
    }

    if (filter.major || filter.minor) {
        bpf_program__set_autoload(skel->progs.crypt_map, false);
        bpf_program__set_autoload(skel->progs.crypt_convert_entry, false);
        bpf_program__set_autoload(skel->progs.crypt_work_queued, false);
        bpf_program__set_autoload(skel->progs.crypt_worker_started, false);
        bpf_program__set_autoload(skel->progs.crypt_write_crypto_done, false);
        bpf_program__set_autoload(skel->progs.crypt_read_crypto_done, false);
        bpf_program__set_autoload(skel->progs.crypt_device_submit, false);
        bpf_program__set_autoload(skel->progs.crypt_device_done, false);
    } else {
        bpf_program__set_autoload(skel->progs.block_device_submit, false);
    }

    err = cryptmon_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %d\n", err);
        goto cleanup;
    }

    if (filter.major || filter.minor) {
        err = bpf_map_update_elem(bpf_map__fd(skel->maps.device_config),
                                  &config_key, &filter, BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to configure device %s: %s\n",
                    argv[2], strerror(errno));
            goto cleanup;
        }
        printf("Tracing block device %s (%u:%u)\n", argv[2],
               filter.major, filter.minor);
    }

    err = cryptmon_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        goto cleanup;
    }

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64, handle_event,
                          handle_lost_events, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
		err = -errno;
        goto cleanup;
    }

    while (!stop) {
        err = perf_buffer__poll(pb, 1000);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "perf_buffer__poll error: %d\n", err);
            break;
        }
    }

    if (stop && err == -EINTR)
        err = 0;

    perf_buffer__free(pb);
cleanup:
    cryptmon_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}

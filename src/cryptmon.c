#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
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
    printf("pid=%-8u comm=%-16s op=%-7s bytes=%-8u cipher=%-16s "
           "convert=%10.3f us calls=%-3u dm_total=%10.3f us\n",
           e->pid, e->comm, op_name(e->op), e->bytes, e->cipher,
           e->convert_time_ns / 1000.0, e->convert_calls,
           e->dm_total_time_ns / 1000.0);
}

static void handle_lost_events(void *ctx, int cpu, unsigned long long count) {
    (void)ctx;
    fprintf(stderr, "Lost %llu events on CPU %d\n", count, cpu);
}

int main() {
    struct cryptmon_bpf *skel;
    struct perf_buffer *pb;
    int err = 0;

    printf("crypt_mon is running... (Ctrl+C to stop)\n");
    signal(SIGINT, sig_handler);

    skel = cryptmon_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF program\n");
        return 1;
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

    perf_buffer__free(pb);
cleanup:
    cryptmon_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}

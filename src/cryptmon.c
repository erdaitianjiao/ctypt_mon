#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "cryptmon.h"
#include "cryptmon.skel.h"

static volatile int stop = 0;
void sig_handler(int sig) { stop = 1; }

static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
    const struct event *e = data;
    printf("pid=%-8d comm=%-16s cipher=%-16s crypt_time=%10llu us  total_time=%10llu us\n",
           e->pid, e->comm, e->cipher,
           e->crypt_time_ns / 1000, e->total_time_ns / 1000);
}

int main() {
    struct cryptmon_bpf *skel;
    struct perf_buffer *pb;
    int err;

    printf("crypt_mon is running... (Ctrl+C to stop)\n");
    signal(SIGINT, sig_handler);

    skel = cryptmon_bpf__open_and_load();
    if (!skel) return 1;

    err = cryptmon_bpf__attach(skel);
    if (err) goto cleanup;

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
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

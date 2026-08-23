#ifndef __CRYPTMON_H
#define __CRYPTMON_H

enum cryptmon_stage {
    CRYPTMON_STAGE_QUEUE      = 1U << 0,
    CRYPTMON_STAGE_CRYPTO     = 1U << 1,
    CRYPTMON_STAGE_DEVICE     = 1U << 2,
    CRYPTMON_STAGE_COMPLETION = 1U << 3,
};

enum cryptmon_event_type {
    CRYPTMON_EVENT_DM = 0,
    CRYPTMON_EVENT_BLOCK = 1,
};

struct device_filter {
    unsigned int major;
    unsigned int minor;
};

struct event {
    unsigned int type;
    unsigned int pid;
    unsigned int op;
    unsigned int bytes;
    unsigned int stage_mask;
    unsigned int dev_major;
    unsigned int dev_minor;
    char comm[16];
    char cipher[32];
    unsigned long long crypto_queue_time_ns;
    unsigned long long submit_queue_time_ns;
    unsigned long long workqueue_time_ns;
    unsigned long long queue_time_ns;
    unsigned long long crypto_time_ns;
    unsigned long long device_time_ns;
    unsigned long long completion_time_ns;
    unsigned long long total_time_ns;
};

#endif

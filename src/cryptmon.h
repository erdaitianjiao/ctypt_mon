#ifndef __CRYPTMON_H
#define __CRYPTMON_H

struct event {
    unsigned int pid;
    unsigned int op;
    unsigned int bytes;
    unsigned int convert_calls;
    char comm[16];
    char cipher[32];
    unsigned long long convert_time_ns;
    unsigned long long dm_total_time_ns;
};

#endif

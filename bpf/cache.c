#include <bpf/bpf_endian.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <asm/errno.h>
#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

volatile const __u32 monitor_pid;

char __license[] SEC("license") = "Dual MIT/GPL";

#ifndef FAULT_FLAG_MINOR
#define FAULT_FLAG_MINOR 0x1
#endif

// which fd need to be monitoring
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);  // pid
    __type(value, __u32);// always true
} monitor_fd SEC(".maps");

struct global_stats {
    __u64 minor_faults;   // minor fault count
    __u64 major_faults;   // major fault count
    __u64 page_accesses;  // total page accesses count
};

// record total cache missing count
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct global_stats);
} global_stats_map SEC(".maps");

struct trace_entry {
    short unsigned int type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
} __attribute__((preserve_access_index));
struct syscall_trace_enter {
    struct trace_entry ent;
    int nr;
    long unsigned int args[0];
} __attribute__((preserve_access_index));

// which fd need to be monitoring
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, int);  // pid
    __type(value, int);// always true
} read_fd_cache SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint_enter_read(struct syscall_trace_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    if (id >> 32 != monitor_pid) {
        return 0;
    }
    __u32 fd = (__u32)ctx->args[0];
    __u32 *exist = bpf_map_lookup_elem(&monitor_fd, &fd);
    if (!exist) {
        bpf_printk("read enter(no): %d, %d", id >> 32, fd);
        return 0;
    }
    bpf_map_update_elem(&read_fd_cache, &id, &fd, 0);
    bpf_printk("read enter: %d, %d", id >> 32, fd);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint_exit_read(struct syscall_trace_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    if (id >> 32 != monitor_pid) {
        return 0;
    }
    bpf_map_delete_elem(&read_fd_cache, &id);
    bpf_printk("read end: %d", id >> 32);
    return 0;
}

SEC("kprobe/handle_mm_fault")
int handle_mm_fault(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    int *fd = bpf_map_lookup_elem(&read_fd_cache, &id);
    if (fd) {
        int key = 0;
        struct global_stats *stats = bpf_map_lookup_elem(&global_stats_map, &key);
        if (!stats) {
            bpf_printk("stats is null at fault");
            return 0;
        }

        unsigned int fault_flags = (unsigned int)PT_REGS_PARM3(ctx);
        if (fault_flags & FAULT_FLAG_MINOR) {
            __sync_fetch_and_add(&stats->minor_faults, 1);
            bpf_printk("minor fault: %d, %d", *fd, fault_flags);
        } else {
            bpf_printk("major fault: %d", *fd, fault_flags);
            __sync_fetch_and_add(&stats->major_faults, 1);
        }
    }
    return 0;
}

SEC("kprobe/mark_page_accessed")
int mark_page_accessed(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();
    int *fd = bpf_map_lookup_elem(&read_fd_cache, &id);
    if (fd) {
        int key = 0;
        struct global_stats *stats = bpf_map_lookup_elem(&global_stats_map, &key);
        if (!stats) {
            bpf_printk("mark page accessed: %d, no status", *fd);
            return 0;
        }
        __sync_fetch_and_add(&stats->page_accesses, 1);
        bpf_printk("mark page accessed: %d, status: %lld", *fd, stats);
    }
    return 0;
}
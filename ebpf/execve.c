#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_ARGV_LEN 128

struct event {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char argv0[MAX_ARGV_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int tracepoint_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;
    const char *filename;
    
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    
    task = (struct task_struct *)bpf_get_current_task();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    
    // 使用 bpf_probe_read_kernel 安全读取 task_struct 成员
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid), &parent->tgid);
    
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // 从 tracepoint 上下文中读取 filename
    filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->argv0, sizeof(e->argv0), filename);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

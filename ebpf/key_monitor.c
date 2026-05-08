// counter.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
//
//
struct trace_even_raw_input_event {
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;

  unsigned int type;
  unsigned int code; // keycode
  int value;
};

// Hasp Map
//
// keycode u32 Value: number
//
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 512);
  __type(key, __u32);
  __type(value, __u64);
} key_counts SEC(".maps");

SEC("tp/input/input_event")

int handle_input_event(struct trace_even_raw_input_event *ctx) {
    if (ctx->type == 1 && ctx->value == 1){
        __u32 key = ctx->code;
        __u64 *count;

        count = bpf_map_lookup_elem(&key_counts, &key);
        if(count){
            __sync_fetch_and_add(count, 1);
        }else {
            __u64 init_val = 1;
            bpf_map_update_elem(&key_counts, &key, &init_val, BPF_ANY);
        }
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

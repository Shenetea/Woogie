#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* map:  key 0 = current valid index (u32) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} token_map SEC(".maps");

/* called every 250 ms via perf-event */
SEC("tp/syscalls/sys_enter_nanosleep")
int roll_token(struct trace_event_raw_sys_enter *ctx)
{
    u32 key = 0, *val;
    val = bpf_map_lookup_elem(&token_map, &key);
    if (!val) return 0;

    *val = (*val + 1) % 5;          // 0→1→2→3→4→0
    bpf_printk("bpf: new token %u\n", *val);
    return 0;
}

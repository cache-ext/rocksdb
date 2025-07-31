#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

#define BPF_STRUCT_OPS(name, args...) \
	SEC("struct_ops/" #name)      \
	BPF_PROG(name, args)

#define MAX_ENTRIES 1000

// Map to track bypassed thread IDs
// If a TID is in this map, it will bypass page cache and use direct I/O
// If not, it will use page cache normally
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);	
	__type(key, __u32);
	__type(value, __u8);
} bypassed_tids SEC(".maps");

#ifdef BPF_DEBUG
// Map to track admission statistics
// Key 0: count of bypassed admissions (returned true)
// Key 1: count of normal admissions (returned false)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} admission_stats SEC(".maps");
#endif

bool BPF_STRUCT_OPS(admit_hook_admit_folio, struct cache_ext_admission_ctx *admission_ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = pid_tgid & 0xffffffff;
	bool result;
	
	__u8 *should_bypass = bpf_map_lookup_elem(&bypassed_tids, &tid);
	
	if (should_bypass) { // TID should bypass - skip page cache (return true)
		result = true;
	} else { // TID not in bypass list - use page cache normally (return false)
		result = false;
	}

#ifdef BPF_DEBUG
	__u32 key = result ? 0 : 1; // Key 0 for bypass, 1 for normal
	__u64 *count = bpf_map_lookup_elem(&admission_stats, &key);
	if (count) {
		__sync_fetch_and_add(count, 1);
	}
#endif

	return result;
}

SEC(".struct_ops.link")
struct page_cache_ext_ops admit_hook_ops = {
	.admit_folio = (void *)admit_hook_admit_folio,
};
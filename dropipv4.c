#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <arpa/inet.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u16);
	__uint(max_entries, 1000);
} rxcnt SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u16);
	__uint(max_entries, 1000);
} port SEC(".maps");

SEC("xdp_drop_ipv4") int drop_packets(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 key = 0;
	uint32_t tcp_port;
	struct ethhdr *ether = data;

	if ((void *)(ether + 1) > (void *)ctx->data_end) {
		return XDP_DROP; /* malformed packet */
	}

	if (ether->h_proto != htons(ETH_P_IP)) {
		return XDP_PASS;
	}
	struct iphdr *ip = (struct iphdr *)(ether + 1);
	if ((void *)(ip + 1) > (void *)ctx->data_end) {
		return XDP_DROP; /* malformed packet */
	}

	if (ip->protocol != IPPROTO_TCP) {
		return XDP_PASS;
	}
	struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
	if ((void *)(tcp + 1) > (void *)ctx->data_end) {
		return XDP_DROP; /* malformed packet */
	}

	tcp_port = ntohs(tcp->dest);

	// Retrieve the allowed port from the map
	__u16 *port_ptr = bpf_map_lookup_elem(&port, &key);

	if (!port_ptr) {
		// Port not found in the map, use a default action (pass or drop)
		return XDP_PASS;
	}

	__u16 allowed_port = *port_ptr;
	//
	if (data + sizeof(struct ethhdr) > data_end)
		return XDP_DROP;

	if (tcp_port == allowed_port) {
		// Packet has IP and TCP headers, and the destination port is 8080.
		// Drop the packet.
		__u16 *packet_count = bpf_map_lookup_elem(&rxcnt, &key);
		if (packet_count)
			*packet_count += 1;
		return XDP_DROP;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
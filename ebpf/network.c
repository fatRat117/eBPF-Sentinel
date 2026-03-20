#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define ETH_HLEN 14
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17
#define IP_PROTO_ICMP 1

// 采样配置 - 每N个包采样1个
#define SAMPLE_RATE 100  // 每100个包采样1个，既能减少事件量又能保证检测到

struct net_event {
    u32 pid;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u8 direction;
    u32 packet_size;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} net_events SEC(".maps");

// 采样计数器
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u64);
} sample_counter SEC(".maps");

// 解析IP协议号
static __always_inline u8 get_ip_protocol(void *data, void *data_end) {
    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end)
        return 0;
    return ip->protocol;
}

// 解析源IP
static __always_inline u32 get_src_ip(void *data, void *data_end) {
    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end)
        return 0;
    return bpf_ntohl(ip->saddr);
}

// 解析目的IP
static __always_inline u32 get_dst_ip(void *data, void *data_end) {
    struct iphdr *ip = data;
    if ((void *)(ip + 1) > data_end)
        return 0;
    return bpf_ntohl(ip->daddr);
}

// 解析源端口
static __always_inline u16 get_src_port(void *data, void *data_end, u8 protocol) {
    if (protocol == IP_PROTO_TCP) {
        struct tcphdr *tcp = data;
        if ((void *)(tcp + 1) > data_end)
            return 0;
        return bpf_ntohs(tcp->source);
    } else if (protocol == IP_PROTO_UDP) {
        struct udphdr *udp = data;
        if ((void *)(udp + 1) > data_end)
            return 0;
        return bpf_ntohs(udp->source);
    }
    return 0;
}

// 解析目的端口
static __always_inline u16 get_dst_port(void *data, void *data_end, u8 protocol) {
    if (protocol == IP_PROTO_TCP) {
        struct tcphdr *tcp = data;
        if ((void *)(tcp + 1) > data_end)
            return 0;
        return bpf_ntohs(tcp->dest);
    } else if (protocol == IP_PROTO_UDP) {
        struct udphdr *udp = data;
        if ((void *)(udp + 1) > data_end)
            return 0;
        return bpf_ntohs(udp->dest);
    }
    return 0;
}

// 采样检查 - 简单的计数器采样
static __always_inline bool should_sample(u32 direction) {
    u32 key = direction;
    u64 *counter = bpf_map_lookup_elem(&sample_counter, &key);
    
    u64 new_val = 1;
    if (counter) {
        new_val = *counter + 1;
    }
    
    bpf_map_update_elem(&sample_counter, &key, &new_val, BPF_ANY);
    
    return (new_val % SAMPLE_RATE) == 0;
}

// 处理网络包
static __always_inline int process_packet(struct __sk_buff *skb, u8 direction) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // 检查以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    
    // 只处理IPv4
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return 0;
    
    void *ip_data = data + ETH_HLEN;
    
    u8 protocol = get_ip_protocol(ip_data, data_end);
    if (protocol != IP_PROTO_TCP && protocol != IP_PROTO_UDP && protocol != IP_PROTO_ICMP)
        return 0;
    
    // 采样检查 - 只处理每N个包中的1个
    if (!should_sample(direction)) {
        return 0;
    }
    
    // 获取传输层数据
    struct iphdr *ip = ip_data;
    u8 ip_header_len = ip->ihl * 4;
    void *transport_data = ip_data + ip_header_len;
    
    u16 src_port = get_src_port(transport_data, data_end, protocol);
    u16 dst_port = get_dst_port(transport_data, data_end, protocol);
    
    // 尝试提交事件（非阻塞）
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e)
        return 0;
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->src_ip = get_src_ip(ip_data, data_end);
    e->dst_ip = get_dst_ip(ip_data, data_end);
    e->protocol = protocol;
    e->direction = direction;
    e->packet_size = skb->len;
    e->src_port = src_port;
    e->dst_port = dst_port;
    
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// TC ingress程序 - 入站流量
SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    process_packet(skb, 0);
    return 0;
}

// TC egress程序 - 出站流量
SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    process_packet(skb, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

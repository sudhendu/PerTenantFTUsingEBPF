#include <bcc/proto.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/icmpv6.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#include <net/inet_sock.h>
#include <uapi/linux/bpf.h>
//#include <linux/bpf.h>
//#include "/home/ece792/prototype-kernel/kernel/samples/bpf/bpf_helpers.h"
#pragma clang diagnostic pop

#define bpf_memcpy __builtin_memcpy

// Event structure
struct route_evt_t {
    /* Routing information */
    char ifname[IFNAMSIZ];  // To store interface name
    u64 netns;            // To store namespace ID
    char func_name[100];  // To store networking kernel function name

    u64 ts;         // To store timestamp

    /* Packet type (IPv4 or IPv6) and address */
    u64 ip_version; // familiy (IPv4 or IPv6)
    u64 icmptype;   // To store ICMP packet type
    u64 icmpid;     // In practice, this is the PID of the ping process (see "ident" field in https://github.com/iputils/iputils/blob/master/ping_common.c)
    u64 icmpseq;    // Sequence number
    u64 saddr[2];   // Source address. IPv4: store in saddr[0]
    u64 daddr[2];   // Dest   address. IPv4: store in daddr[0]
};
BPF_PERF_OUTPUT(route_evt);

#define MAC_HEADER_SIZE 14;
#define member_address(source_struct, source_member)            \
    ({                                                          \
        void* __ret;                                            \
        __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \
        __ret;                                                  \
    })
#define member_read(destination, source_struct, source_member)  \
  do{                                                           \
    bpf_probe_read(                                             \
      destination,                                              \
      sizeof(source_struct->source_member),                     \
      member_address(source_struct, source_member)              \
    );                                                          \
  } while(0)

/**
  * Common tracepoint handler. Detect IPv4/IPv6 ICMP echo request and replies and
  * emit event with address, interface and namespace.
  */
static inline int do_trace(void* ctx, struct sk_buff* skb, char* func_name)
{
    // Prepare event for userland
    struct route_evt_t evt = {};

    // Store current time in nanoseconds in the event structure
    evt.ts = bpf_ktime_get_ns();

    // Compute MAC header address
    char* head;
    u16 mac_header;

    member_read(&head, skb, head);
    member_read(&mac_header, skb, mac_header);

    // Compute IP Header address
    char* ip_header_address = head + mac_header + MAC_HEADER_SIZE;

    // Abstract IPv4 / IPv6
    u8 proto_icmp;
    u8 proto_icmp_echo_request;
    u8 proto_icmp_echo_reply;
    u8 icmp_offset_from_ip_header;
    u8 l4proto;

    // Load IP protocol version
    bpf_probe_read(&evt.ip_version, sizeof(u8), ip_header_address);
    evt.ip_version = evt.ip_version >> 4 & 0xf;

    // Filter IP packets
    if (evt.ip_version == 4) {
        // Load IP Header
        struct iphdr iphdr;

        bpf_probe_read(&iphdr, sizeof(iphdr), ip_header_address);

        // Load protocol and address
        icmp_offset_from_ip_header = iphdr.ihl * 4;
        l4proto      = iphdr.protocol;
        evt.saddr[0] = iphdr.saddr;
        evt.daddr[0] = iphdr.daddr;

        // Load constants
        proto_icmp = IPPROTO_ICMP;
        proto_icmp_echo_request = ICMP_ECHO;
        proto_icmp_echo_reply   = ICMP_ECHOREPLY;
    } else {
        return 0;
    }

    // Filter ICMP packets
    if (l4proto != proto_icmp) {
       return 0;
    }

    // Compute ICMP header address and load ICMP header
    char* icmp_header_address = ip_header_address + icmp_offset_from_ip_header;
    struct icmphdr icmphdr;
    bpf_probe_read(&icmphdr, sizeof(icmphdr), icmp_header_address);

    // Filter ICMP echo request and echo reply
    // Not required if VxLAN encapsulated packets to be seen too
    if (icmphdr.type != proto_icmp_echo_request && icmphdr.type != proto_icmp_echo_reply) {
       return 0;
    }

    // Get ICMP info
    evt.icmptype = icmphdr.type;
    evt.icmpid   = icmphdr.un.echo.id;
    evt.icmpseq  = icmphdr.un.echo.sequence;

    // Fix endian
    evt.icmpid  = be16_to_cpu(evt.icmpid);
    evt.icmpseq = be16_to_cpu(evt.icmpseq);

    // Get device pointer, we'll need it to get the name and network namespace
    struct net_device *dev;
    member_read(&dev, skb, dev);

    // Load interface name
    bpf_probe_read(&evt.ifname, IFNAMSIZ, dev->name);

#ifdef CONFIG_NET_NS
    struct net* net;

    // Get netns id. The code below is equivalent to: evt.netns = dev->nd_net.net->ns.inum
    possible_net_t *skc_net = &dev->nd_net;
    member_read(&net, skc_net, net);
    struct ns_common* ns = member_address(net, ns);
    member_read(&evt.netns, ns, inum);
#endif

    // Set function name in which packet currently is in the event
    bpf_probe_read(&(evt.func_name), 100, func_name);

    // Send event
    route_evt.perf_submit(ctx, &evt, sizeof(evt));

    return 0;
}

// Attach networking kernel functions to tracepoints
TRACEPOINT_PROBE(net, netif_rx) {
    char func_name[] = "netif_rx";
    return do_trace(args, (struct sk_buff*)args->skbaddr, func_name);
}

TRACEPOINT_PROBE(net, net_dev_queue) {
    char func_name[] = "net_dev_queue";
    return do_trace(args, (struct sk_buff*)args->skbaddr, func_name);
}

TRACEPOINT_PROBE(net, napi_gro_receive_entry) {
    char func_name[] = "napi_gro_receive_entry";
    return do_trace(args, (struct sk_buff*)args->skbaddr, func_name);
}

TRACEPOINT_PROBE(net, netif_receive_skb_entry) {
    char func_name[] = "netif_receive_skb_entry";
    return do_trace(args, (struct sk_buff*)args->skbaddr, func_name);
}

TRACEPOINT_PROBE(net, net_dev_start_xmit) {
    char func_name[] = "net_dev_start_xmit";
    return do_trace(args, (struct sk_buff*)args->skbaddr, func_name);
}

TRACEPOINT_PROBE(net, net_dev_xmit) {
    char func_name[] = "net_dev_xmit";
    return do_trace(args, (struct sk_buff*)args->skbaddr, func_name);
}

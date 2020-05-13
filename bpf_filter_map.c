#include <linux/ip.h>
//#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/icmp.h>
//#include <linux/icmpv6.h>
//#include <net/inet_sock.h>
#include <linux/stddef.h>
#include <linux/bpf.h>
//#include <uapi/linux/string.h>
#include <linux/pkt_cls.h>
#include <stddef.h>
#include "bpf_helpers.h"
#include "bpf_api.h"
#define DEBUGON 1

/* compiler workaround */
/*#define bpf_htonl __builtin_bswap32
#define bpf_memcpy __builtin_memcpy
 */

#define ICMP_PING 8

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))
#define ICMP_CSUM_SIZE sizeof(__u16)

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_CSUM_SIZE sizeof(__sum16)

#define trace_printk(fmt, ...) do { \
	char _fmt[] = fmt; \
	bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
} while (0)

/* TODO: Describe what this PIN_GLOBAL_NS value 2 means???
 *
 * A file is automatically created here:
 *  /sys/fs/bpf/tc/globals/egress_ifindex
 */

struct map_key
{
	__u32 destination_ip;
	__u32 tenant_id;
};

struct map_entry
{
	__u32 device_id;
	__u8 dst_mac[6];
};

struct bpf_elf_map SEC("maps") egress_ifindex = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(struct map_key),
	.size_value = sizeof(struct map_entry),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = 256,
};


struct bpf_elf_map SEC("maps") deviceid_tenant = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(__u32),
	.size_value = sizeof(__u32),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = 256,
};


	SEC("classifier")
int cls_main(struct __sk_buff *skb)
{

	__u32 proto = skb->protocol;
	__u32 iface = skb->ifindex;


	__u32 *tenantId = bpf_map_lookup_elem(&deviceid_tenant, &iface);

	if(tenantId == NULL)
		trace_printk("Tenant ID not found\n");
	else
	{

		// Getting pointer to start and end of data
		void *data = (void *)(long)skb->data;
		void *data_end = (void *)(long)skb->data_end;

		// Check that packet has enough data, so that we can access
		// appropriate headers
		if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
			return TC_ACT_UNSPEC;

		// Getting pointers to ethernet and IP headers
		struct ethhdr *ethernet_header = data;
		struct iphdr *ip_header = data + sizeof(struct ethhdr);
		struct icmphdr *icmp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));


		// Retrieve source and destination IP addresses from the IP header of the packet
		__u32 source_ip = ip_header->saddr;
		__u32 destination_ip = ip_header->daddr;

		struct map_key key;
		key.destination_ip = destination_ip;
		key.tenant_id = *(tenantId);

		/* Lookup what ifindex to redirect packets to */
		struct map_entry *found_entry = bpf_map_lookup_elem(&egress_ifindex, &key);

		if(found_entry == NULL)
			trace_printk("No entry for a tenant and its destination IP found in the map\n");
		else
		{
			//trace_printk("In classifier protocol %lu %lu\n", proto, found_entry->device_id);

			if(proto == 8) {
				/*Let's grab the MAC address.
				 * We need to copy them out, as they are 48 bits long */
				__u8 dst_mac[ETH_ALEN];

				dst_mac[0] = found_entry->dst_mac[0];
				dst_mac[1] = found_entry->dst_mac[1];
				dst_mac[2] = found_entry->dst_mac[2];
				dst_mac[3] = found_entry->dst_mac[3];
				dst_mac[4] = found_entry->dst_mac[4];
				dst_mac[5] = found_entry->dst_mac[5];

				/* Change the MAC addresses */
				bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), dst_mac, ETH_ALEN, BPF_F_RECOMPUTE_CSUM);

				return bpf_redirect(found_entry->device_id, 0);
			}
		}
	}
	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";

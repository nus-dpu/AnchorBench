#ifndef _SC_UTILS_PKTGEN_H_
#define _SC_UTILS_PKTGEN_H_

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_sctp.h>

#define IP_DEFTTL  64   /* from RFC 1340. */

int sc_util_copy_buf_to_pkt(void *buf, unsigned len, struct rte_mbuf *pkt, unsigned offset);
int sc_util_generate_packet_burst_proto(struct rte_mempool *mp, struct rte_mbuf **pkts_burst, 
		struct rte_ether_hdr *eth_hdr, uint8_t vlan_enabled, void *ip_hdr,
		uint8_t ipv4, uint8_t proto, void *proto_hdr, int nb_pkt_per_burst, 
		uint8_t pkt_len, uint8_t nb_pkt_segs);
int sc_util_initialize_eth_header(struct rte_ether_hdr *eth_hdr,
		struct rte_ether_addr *src_mac, struct rte_ether_addr *dst_mac, 
		uint16_t ether_type, uint8_t vlan_enabled, uint16_t van_id);
int sc_util_initialize_arp_header(struct rte_arp_hdr *arp_hdr,
		struct rte_ether_addr *src_mac, struct rte_ether_addr *dst_mac,
		uint32_t src_ip, uint32_t dst_ip, uint32_t opcode);
int sc_util_initialize_udp_header(struct rte_udp_hdr *udp_hdr, uint16_t src_port,
		uint16_t dst_port, uint16_t pkt_data_len, uint16_t *pkt_len);
int sc_util_initialize_tcp_header(struct rte_tcp_hdr *tcp_hdr, uint16_t src_port,
		uint16_t dst_port, uint16_t pkt_data_len, uint16_t *pkt_len);
int sc_util_initialize_sctp_header(struct rte_sctp_hdr *sctp_hdr, uint16_t src_port,
		uint16_t dst_port, uint16_t pkt_data_len, uint16_t *pkt_len);
int sc_util_initialize_ipv6_header_proto(struct rte_ipv6_hdr *ip_hdr, uint8_t *src_addr,
		uint8_t *dst_addr, uint16_t pkt_data_len, uint8_t proto, uint16_t *pkt_len);
int sc_util_initialize_ipv4_header_proto(struct rte_ipv4_hdr *ip_hdr, uint32_t src_addr,
		uint32_t dst_addr, uint16_t pkt_data_len, uint8_t proto, uint16_t *pkt_len);

#endif
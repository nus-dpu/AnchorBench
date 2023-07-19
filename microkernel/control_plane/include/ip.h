#ifndef _IP_H_
#define _IP_H_

#include <sys/socket.h>
#include <linux/ip.h>
#include <stdint.h>

#include "err.h"
#include "netif.h"
#include "ip_addr.h"

/** This is the common part of all PCB types. It needs to be at the
   beginning of a PCB type definition. It is located here so that
   changes to this common part are made in one location instead of
   having to change all PCB structs. */
#define IP_PCB \
    /* ip addresses in network byte order */ \
    ip_addr_t local_ip; \
    ip_addr_t remote_ip; \
    /* Socket options */  \
    uint8_t so_options;      \
    /* Type Of Service */ \
    uint8_t tos;              \
    /* Time To Live */     \
    uint8_t ttl

struct ip_pcb {
/* Common members of all PCB types */
    IP_PCB;
};

/* Macros to get struct ip_hdr fields: */
#define IPH_V(hdr)  ((hdr)->version)
#define IPH_HL(hdr) ((hdr)->ihl)
#define IPH_TOS(hdr) ((hdr)->tos)
#define IPH_LEN(hdr) ((hdr)->tot_len)
#define IPH_ID(hdr) ((hdr)->id)
#define IPH_OFFSET(hdr) ((hdr)->frag_off)
#define IPH_TTL(hdr) ((hdr)->ttl)
#define IPH_PROTO(hdr) ((hdr)->protocol)
#define IPH_CHKSUM(hdr) ((hdr)->check)

/* Macros to set struct ip_hdr fields: */
#define IPH_V_SET(hdr, v) (hdr)->version = (v)
#define IPH_HL_SET(hdr, hl) (hdr)->ihl = (hl)
#define IPH_TOS_SET(hdr, tos) (hdr)->tos = (tos)
#define IPH_LEN_SET(hdr, len) (hdr)->tot_len = (len)
#define IPH_ID_SET(hdr, nid) (hdr)->id = (nid)
#define IPH_FRAG_OFFSET_SET(hdr, flag, off) (hdr)->frag_off = (htons(flag | off))
#define IPH_TTL_SET(hdr, ttl) (hdr)->ttl = (uint8_t)(ttl)
#define IPH_PROTO_SET(hdr, proto) (hdr)->protocol = (uint8_t)(proto)
#define IPH_CHKSUM_SET(hdr, chksum) (hdr)->check = (check)

/** Global variables of this module, kept in a struct for efficient access using base+index. */
struct ip_data {
    /** The interface that accepted the packet for the current callback invocation. */
    struct netif * current_netif;
    /** The interface that received the packet for the current callback invocation. */
    struct netif * current_input_netif;
    /** Header of the input packet currently being processed. */
    struct iphdr * current_ip4_header;
    /** Total header length of current_ip4/6_header (i.e. after this, the UDP/TCP header starts) */
    uint16_t current_ip_header_tot_len;
    /** Source IP address of current_header in network byte order */
    ip_addr_t current_iphdr_src;
    /** Destination IP address of current_header in network byte order */
    ip_addr_t current_iphdr_dest;
};

extern struct ip_data ip_data;

/** Gets an IP pcb option (SOF_* flags) */
#define ip_get_option(pcb, opt)   ((pcb)->so_options & (opt))
/** Sets an IP pcb option (SOF_* flags) */
#define ip_set_option(pcb, opt)   ((pcb)->so_options |= (opt))
/** Resets an IP pcb option (SOF_* flags) */
#define ip_reset_option(pcb, opt) ((pcb)->so_options &= ~(opt))

/** Get the interface that accepted the current packet.
 * This may or may not be the receiving netif, depending on your netif/network setup.
 * This function must only be called from a receive callback (udp_recv,
 * raw_recv, tcp_accept). It will return NULL otherwise. */
#define ip_current_netif()      (ip_data.current_netif)
/** Get the interface that received the current packet.
 * This function must only be called from a receive callback (udp_recv,
 * raw_recv, tcp_accept). It will return NULL otherwise. */
#define ip_current_input_netif() (ip_data.current_input_netif)
/** Total header length of ip(6)_current_header() (i.e. after this, the UDP/TCP header starts) */
#define ip_current_header_tot_len() (ip_data.current_ip_header_tot_len)
/** Source IP address of current_header */
#define ip_current_src_addr()   (&ip_data.current_iphdr_src)
/** Destination IP address of current_header */
#define ip_current_dest_addr()  (&ip_data.current_iphdr_dest)

extern err_t ip4_output_if(struct pbuf * p, const ip4_addr_t * src, const ip4_addr_t * dest, uint8_t ttl, uint8_t tos, uint8_t proto, struct netif * netif);
#define ip_output_if(p, src, dest, ttl, tos, proto, netif)  ip4_output_if(p, src, dest, ttl, tos, proto, netif)

extern struct netif * ip4_route(const ip4_addr_t * src, const ip4_addr_t * dest);
#define ip_route(src, dest) ip4_route(src, dest)

#define ip_netif_get_local_ip(netif, dest)  ip4_netif_get_local_ip(netif)
#define ip4_netif_get_local_ip(netif)       (((netif) != NULL) ? netif_ip4_addr(netif) : NULL)

#endif  /* _IP_H_ */
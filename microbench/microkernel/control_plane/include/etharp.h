#ifndef _LYRA_ETHARP_H_
#define _LYRA_ETHARP_H_

#include <linux/if_ether.h>
#include <linux/if_arp.h>

#include "err.h"
#include "init.h"
#include "ip_addr.h"
#include "netif.h"

/** the ARP message, see RFC 826 ("Packet format") */
struct eth_arphdr {
    uint16_t ar_hrd;            /* Format of hardware address.  */
    uint16_t ar_pro;            /* Format of protocol address.  */
    uint8_t ar_hln;             /* Length of hardware address.  */
    uint8_t ar_pln;             /* Length of protocol address.  */
    uint16_t ar_op;             /* ARP opcode (command).  */
    uint8_t ar_sha[ETH_ALEN];   /* Sender hardware address.  */
    uint32_t ar_sip;            /* Sender IP address.  */
    uint8_t ar_tha[ETH_ALEN];   /* Target hardware address.  */
    uint32_t ar_tip;            /* Target IP address.  */
} __attribute__ ((__packed__));

extern void etharp_input(struct pbuf * p, struct netif * netif);
extern int etharp_output(struct netif * netif, struct pbuf * q, const ip4_addr_t * ipaddr);
extern err_t etharp_query(struct netif * netif, ip4_addr_t * ipaddr, struct pbuf * q);
extern err_t etharp_request(struct netif * netif, ip4_addr_t * ipaddr);

extern int __init arp_init(void);

#endif  /* _LYRA_ETHARP_H_ */
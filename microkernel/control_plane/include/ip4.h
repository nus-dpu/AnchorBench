#ifndef _LYRA_IP4_H_
#define _LYRA_IP4_H_

#include "err.h"
#include "netif.h"
#include "pbuf.h"

/* Size of the IPv4 header. Same as 'sizeof(struct ip_hdr)'. */
#define IP_HLEN sizeof(struct iphdr)

#ifndef IP_RF
#define IP_RF       0x8000U        /* reserved fragment flag */
#endif  /* IP_RF */

#ifndef IP_DF
#define IP_DF       0x4000U        /* don't fragment flag */
#endif  /* IP_DF */

#ifndef IP_MF
#define IP_MF       0x2000U        /* more fragments flag */
#endif  /* IP_MF */

#ifndef IP_OFFMASK
#define IP_OFFMASK  0x1fffU   /* mask for fragmenting bits */
#endif  /* IP_OFFMASK */

#define ip4_addr_ismulticast(addr1)     (((addr1)->addr & htonl(0xf0000000UL)) == htonl(0xe0000000UL))
#define ip4_addr_islinklocal(addr1)     (((addr1)->addr & htonl(0xffff0000UL)) == htonl(0xa9fe0000UL))

/**
 * Determine if two address are on the same network.
 *
 * @arg addr1 IP address 1
 * @arg addr2 IP address 2
 * @arg mask network identifier mask
 * @return !0 if the network identifiers of both address match
 */
#define ip4_addr_netcmp(addr1, addr2, mask) (((addr1)->addr & \
                                              (mask)->addr) == \
                                             ((addr2)->addr & \
                                              (mask)->addr))
#define ip4_addr_cmp(addr1, addr2)      ((addr1)->addr == (addr2)->addr)

extern err_t ip4_input(struct pbuf * p, struct netif * inp);
extern err_t ip4_output_if_src(struct pbuf * p, const ip4_addr_t * src, const ip4_addr_t * dest,
            uint8_t ttl, uint8_t tos, uint8_t proto, struct netif * netif);
#endif  /* _LYRA_IP4_H_ */
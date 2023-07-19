#ifndef _LYRA_NETIF_H_
#define _LYRA_NETIF_H_

#include <stdint.h>
#include <stdbool.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "err.h"
#include "list.h"
#include "ip_addr.h"

#define NETIF_MAX_NAME_LEN  16

struct netif;
struct pbuf;

/** Must be the maximum of all used hardware address lengths
    across all types of interfaces in use.
    This does not have to be changed, normally. */
#ifndef NETIF_MAX_HWADDR_LEN
#define NETIF_MAX_HWADDR_LEN 6U
#endif

/** Function prototype for netif->input functions. This function is saved as 'input'
 * callback function in the netif struct. Call it when a packet has been received.
 *
 * @param p The received packet, copied into a pbuf
 * @param netif The netif which received the packet
 */
typedef int (*netif_input_fn)(struct pbuf * p, struct netif * inp);

/** Function prototype for netif->output functions. Called by lwIP when a packet
 * shall be sent. For ethernet netif, set this to 'etharp_output' and set
 * 'linkoutput'.
 *
 * @param netif The netif which shall send a packet
 * @param p The packet to send (p->payload points to IP header)
 * @param ipaddr The IP address to which the packet shall be sent
 */
typedef int (*netif_output_fn)(struct netif * inp, struct pbuf *p, const ip_addr_t * ipaddr);

/** Function prototype for netif->linkoutput functions. Only used for ethernet
 * netifs. This function is called by ARP when a packet shall be sent.
 *
 * @param netif The netif which shall send a packet
 * @param p The packet to send (raw ethernet packet)
 */
typedef err_t (*netif_linkoutput_fn)(struct netif * netif, struct pbuf * p);

struct netif {
    struct list_head list;

    char name[NETIF_MAX_NAME_LEN];
    int port_id;

    /** link level hardware address of this interface */
    struct ether_addr hwaddr;

    char pci_addr[16];

    /** IP address configuration in network byte order */
    ip_addr_t ip_addr;
    ip_addr_t netmask;
    ip_addr_t gw;

    netif_input_fn input;
    netif_output_fn output;
    netif_linkoutput_fn linkoutput;
};

extern struct list_head in_use_iface_list;

#define netif_ip4_addr(netif)    ((ip4_addr_t *)&((netif)->ip_addr))
#define netif_ip4_netmask(netif) ((ip4_addr_t *)&((netif)->netmask))
#define netif_ip4_gw(netif)      ((ip4_addr_t *)&((netif)->gw))

#endif  /* _LYRA_NETIF_H_ */
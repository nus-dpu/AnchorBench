#ifndef _LYRA_ETH_H_
#define _LYRA_ETH_H_

#include "netif.h"
#include "pbuf.h"

#define ETH_HWADDR_LEN  6

#define ETHADDR_COPY(dst, src)  memcpy(dst, src, ETH_HWADDR_LEN)

extern struct ether_addr ethbroadcast;
extern struct ether_addr ethzero;

extern int ethernet_input(struct pbuf * p, struct netif * netif);
extern int ethernet_output(struct netif * netif, struct pbuf * p, struct ether_addr * src, struct ether_addr * dst, uint16_t eth_type);
extern err_t netif_tx_func(struct netif * netif, struct pbuf * p);

#endif  /* _LYRA_ETH_H_ */
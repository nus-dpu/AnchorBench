#ifndef _LYRA_IPC_H_
#define _LYRA_IPC_H_

#include "init.h"
#include "eth.h"
#include "ip4.h"

extern int __init ipc_init(void);

extern int ipc_socket;

typedef enum {
    REQUEST_CORE = 0x1, 
    RELEASE_CORE, 
    REQUEST_COREMASK,
    RELEASE_COREMASK,
    REQUEST_IFACE, 
    CREATE_FLOW,
    ARP_REQUEST,
    UPDATE_ARP_TABLE,
} msg_type_t;

struct ipc_msghdr {
    msg_type_t      type;
    unsigned int    src_core;
    unsigned int    dst_core;
    int             len;
};

struct flow {
    char type[16];
    int prior;
    uint32_t src_ip;
    uint32_t src_ip_mask;
    uint32_t dst_ip;
    uint32_t dst_ip_mask;
    uint16_t src_port;
    uint16_t src_port_mask;
    uint16_t dst_port;
    uint16_t dst_port_mask;
};

struct arp_entry {
    struct ether_addr hwaddr;   /* Hardware address. */
    ip4_addr_t ipaddr;  /* IP address.  */
} __attribute__ ((__packed__));

extern int ipc_update_arp_table(struct arp_entry * entry);

#endif  /* _LYRA_IPC_H_ */
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
    int port;
};

#endif  /* _LYRA_IPC_H_ */
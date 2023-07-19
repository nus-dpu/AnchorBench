#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <stdlib.h>

#include "opt.h"
#include "printk.h"
#include "ipc.h"
#include "core.h"

int ipc_socket;

int ipc_update_arp_table(struct arp_entry * entry) {
    char buf[64] = {0};
    struct ipc_msghdr * msg;

    /* Request iface info from control plane */
    msg = (struct ipc_msghdr *)buf;
    msg->type       = UPDATE_ARP_TABLE;
    msg->dst_core   = 0;
    msg->len        = sizeof(struct arp_entry);

    /* Payload: struct arp_entry, arp mapping we want to install to data plane */
    memcpy(buf + sizeof(struct ipc_msghdr), (void *)entry, sizeof(struct arp_entry));

    for (int i = 1; i < NR_CPUS; i++) {
        if (!core_infos[i].occupied) {
            continue;
        }

        msg->src_core = i;
        if(send(core_infos[i].sockfd, (void *)buf, sizeof(struct ipc_msghdr) + sizeof(struct flow), 0) < 0) {
            pr_crit("fail to send message to control plane!(err: %d)\n", errno);
            return -1;
        }

        pr_debug(IPC_DEBUG, "updating worker ARP table...\n");
    }

    return 0;
}

int __init ipc_init(void) {
    struct sockaddr_un address;
	address.sun_family = AF_UNIX;
	strcpy(address.sun_path, "/tmp/ipc.socket");

    if (remove(address.sun_path) == -1 && errno != ENOENT) {
        pr_crit("Failed remove existing socket file!\n");
        return -1;
    }

    if ((ipc_socket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        pr_crit("Failed to create socket for IPC!\n");
        return -1;
    }

    int flags = fcntl(ipc_socket, F_GETFL);
    if (fcntl(ipc_socket, F_SETFL, flags | O_NONBLOCK) < 0) {
        pr_crit("Failed to set IPC socket to non-blocking mode!\n");
        return -1;
    }

    if (bind(ipc_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        pr_crit("Failed to bind socket!\n");
        return -1;
    }

    if (listen(ipc_socket, 20) < 0) {
        pr_crit("Failed to listen socket!\n");
        return -1;
    }

    return 0;
}
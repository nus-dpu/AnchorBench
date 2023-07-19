#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "opt.h"
#include "dpdk_module.h"
#include "core.h"
#include "cpumask.h"
#include "ipc.h"
#include "mm.h"
#include "printk.h"
#include "netfmt.h"
#include "netif.h"
#include "pbuf.h"

#define MAX_EVENTS  1024

/**
 * Main loop for Lyra
 * * 1. Accept for incoming connections from worker cores 
 * * 2. Allocate/Free CPU/network resources for worker cores
 * * 3. Slow path for network stack
 */
int lyra_loop(void) {
    int epfd, nevent, ret, new_sock;
    struct epoll_event ev, events[MAX_EVENTS];

    /* Create epoll file descriptor */
    epfd = epoll_create1(0);

    if(epfd == -1) {
        pr_crit("fail to create epoll fd in control plane!\n");
        return -1;
    }

    /* Register EPOLLIN event */
    ev.events = EPOLLIN;
    ev.data.fd = ipc_socket;

    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, ipc_socket, &ev);
    if (ret == -1) {
        pr_crit("fail to register epoll event!\n");
        return -1;
    }

    while (1) {
        /* Poll epoll IPC events from workers if there is any */
        nevent = epoll_wait(epfd, events, MAX_EVENTS, 0);
        for(int i = 0; i < nevent; i++) {
            /* New worker thread is connecting to control plane */
            if (events[i].data.fd == ipc_socket) {
                if ((new_sock = accept(ipc_socket, NULL, NULL)) < 0) {
                    pr_warn(" fail to accept incoming connection\n");
                    continue;
                }

                int flags = fcntl(new_sock, F_GETFL);
                if (fcntl(new_sock, F_SETFL, flags | O_NONBLOCK) < 0) {
                    pr_warn("fail to set new socket to non-blocking mode...\n");
                    continue;
                }

                struct epoll_event ev;
                ev.events = EPOLLIN;
                ev.data.fd = new_sock;

                epoll_ctl(epfd, EPOLL_CTL_ADD, new_sock, &ev);

                continue;
            }

            /**
             * Process worker thread request
             * * 1. Request/release CPU core
             * * 2. Request network information (interfaces/ARP table/routing table)
             */
            if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
                close(events[i].data.fd);
                continue;
            } else if (events[i].events & EPOLLIN) {
                handle_read_event(epfd, &events[i]);
            }
        }
    }    
}

int main(int argc, char ** argv) {
    /* Init DPDK module (packet mempool, RX/TX queue, ...) */
    pr_info("init: starting DPDK...\n");
    dpdk_init();

    /* Init CPU allocation status */
    pr_info("init: initializing CPU status...\n");
    sched_init();

    /**
     * Init interprocess communication subsystem
     */
    pr_info("init: starting IPC subsystem...\n");
    ipc_init();

    /* Now enter the main loop */
    pr_info("init: starting Lyra loop...\n");
    lyra_loop();

    return 0;
}

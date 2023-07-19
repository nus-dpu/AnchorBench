#ifndef _OPT_H_
#define _OPT_H_

/** @name Enable/disable debug messages completely (LWIP_DBG_TYPES_ON)
 * @{
 */
/** flag for pr_debug to enable that debug message */
#define DBG_ON	0x80U
/** flag for pr_debug to disable that debug message */
#define DBG_OFF	0x00U

#define IPC_DEBUG       DBG_ON
#define SOCKET_DEBUG    DBG_ON
#define PBUF_DEBUG      DBG_ON
#define FS_DEBUG        DBG_ON
#define SCHED_DEBUG     DBG_OFF
#define STACK_DEBUG     DBG_ON

#define ETH_PAD_SIZE                    0

#define PBUF_LINK_HLEN                  (14 + ETH_PAD_SIZE)
#define PBUF_LINK_ENCAPSULATION_HLEN    0u
#define PBUF_IP_HLEN        20
#define PBUF_TRANSPORT_HLEN 20

#define ARP_QUEUEING    0
#define ARP_TABLE_SIZE  10
#define ARP_MAXAGE      300

/**
 * IP_DEFAULT_TTL: Default value for Time-To-Live used by transport layers.
 */
#define IP_DEFAULT_TTL  255

/**
 * TCP_TTL: Default Time-To-Live value.
 */
#define TCP_TTL         (IP_DEFAULT_TTL)
#define TCP_MSS         536

#endif  /* _OPT_H_ */
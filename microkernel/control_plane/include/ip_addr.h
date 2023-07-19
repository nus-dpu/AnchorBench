#ifndef _LYRA_IP_ADDR_H_
#define _LYRA_IP_ADDR_H_

/** @ingroup ipaddr
 * IP address types for use in ip_addr_t.type member.
 * @see tcp_new_ip_type(), udp_new_ip_type(), raw_new_ip_type().
 */
enum lwip_ip_addr_type {
  /** IPv4 */
  IPADDR_TYPE_V4 =   0U,
  /** IPv6 */
  IPADDR_TYPE_V6 =   6U,
  /** IPv4+IPv6 ("dual-stack") */
  IPADDR_TYPE_ANY = 46U
};

struct ip4_addr {
    uint32_t addr;
};

typedef struct ip4_addr ip4_addr_t;
typedef ip4_addr_t ip_addr_t;

/** 0.0.0.0 */
#define IPADDR_ANY            ((uint32_t)0x00000000UL)
#define IPADDR4_INIT(u32val)  { u32val }

#define IPADDR_COPY(dest, src)  memcpy(dest, src, sizeof(ip4_addr_t))

/** IPv4 only: set the IP address given as an u32_t */
#define ip4_addr_set_u32(dest_ipaddr, src_u32)  ((dest_ipaddr)->addr = (src_u32))
/** IPv4 only: get the IP address as an u32_t */
#define ip4_addr_get_u32(src_ipaddr)            ((src_ipaddr)->addr)

/** Copy IP address - faster than ip4_addr_set: no NULL check */
#define ip4_addr_copy(dest, src)          ((dest).addr = (src).addr)

#define ip4_addr_isany_val(addr1)   ((addr1).addr == IPADDR_ANY)
#define ip4_addr_isany(addr1)       ((addr1) == NULL || ip4_addr_isany_val(*(addr1)))
#define ip_addr_isany(ipaddr)       ip4_addr_isany(ipaddr)

#endif  /* _LYRA_IP_ADDR_H_ */
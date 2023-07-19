#ifndef _LYRA_NETFMT_H_
#define _LYRA_NETFMT_H_

#include <endian.h>

#define ETHER_STRING "%02x:%02x:%02x:%02x:%02x:%02x"
#define ETHER_FMT(m) m[0],m[1],m[2],m[3],m[4],m[5]

#define IP_STRING	"%hhu.%hhu.%hhu.%hhu"

#define LE_IP_FMT(ip)   ((uint8_t *)&(ip))[3], \
					    ((uint8_t *)&(ip))[2], \
 					    ((uint8_t *)&(ip))[1], \
				        ((uint8_t *)&(ip))[0]

#define BE_IP_FMT(ip)   ((uint8_t *)&(ip))[0], \
					    ((uint8_t *)&(ip))[1], \
 					    ((uint8_t *)&(ip))[2], \
				        ((uint8_t *)&(ip))[3]

#if __BYTE_ORDER == __LITTLE_ENDIAN
#	define HOST_IP_FMT(ip)	LE_IP_FMT(ip)
#elif __BYTE_ORDER == __BIG_ENDIAN
#	define HOST_IP_FMT(ip)	BE_IP_FMT(ip)
#endif

#define NET_IP_FMT(ip)	BE_IP_FMT(ip)

#define STR_TO_IP(s)    ((s[0] << 24) | (s[1] << 16) | (s[2] << 8) | (s[3]))

#endif  /* _LYRA_NETFMT_H_ */
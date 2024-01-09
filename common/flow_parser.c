/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include <rte_byteorder.h>
#include <bsd/string.h>

#include <doca_log.h>

#include "flow_parser.h"
#include "utils.h"

DOCA_LOG_REGISTER(FLOW_PARSER);

#define MAX_CMDLINE_INPUT_LEN 512			/* Maximum size of input command  */
#define MAC_ADDR_LEN 6					/* MAC address size in bytes */
#define IP_ADDR_LEN 4					/* IP address size in bytes */
#define MAX_FIELD_INPUT_LEN 128				/* Maximum size of field input */
#define NAME_STR_LEN 5					/* Name string size */
#define FWD_STR_LEN 4					/* Forward string size */
#define MISS_FWD_STR_LEN 9				/* Forward miss string size */
#define MATCH_MASK_STR_LEN 11				/* Match mask string size */
#define MONITOR_STR_LEN 8				/* Monitor string size */
#define ROOT_ENABLE_STR_LEN 12				/* Root enable string size */
#define PORT_ID_STR_LEN 8				/* Port ID string size */
#define PIPE_ID_STR_LEN 8				/* Pipe ID string size */
#define ENTRY_ID_STR_LEN 9				/* Entry ID string size */
#define PIPE_QUEUE_STR_LEN 11				/* Pipe queue string size */
#define PRIORITY_STR_LEN 9				/* Priority string size */
#define FILE_STR_LEN 5					/* File string size */
#define TYPE_STR_LEN 5					/* Type enable string size */
#define HEXADECIMAL_BASE 1				/* Hex base */
#define UINT32_CHANGEABLE_FIELD "0xffffffff"		/* DOCA flow masking for 32 bits value */

#define BE_IPV4_ADDR(a, b, c, d) (RTE_BE32((a << 24) + (b << 16) + (c << 8) + d))	/* Big endian conversion */

/* Set match l4 port */
#define SET_L4_PORT(layer, port, value) \
do {\
	if (match->layer.l4_type_ext == DOCA_FLOW_L4_TYPE_EXT_TCP)\
		match->layer.tcp.l4_port.port = (value);\
	else if (match->layer.l4_type_ext == DOCA_FLOW_L4_TYPE_EXT_UDP)\
		match->layer.udp.l4_port.port = (value);\
} while (0)

doca_error_t parse_ipv4_str(const char *str_ip, doca_be32_t *ipv4_addr) {
	char *ptr;
	int i;
	int ips[4];

	if (strcmp(str_ip, UINT32_CHANGEABLE_FIELD) == 0) {
		*ipv4_addr = UINT32_MAX;
		return DOCA_SUCCESS;
	}
	for (i = 0; i < 3; i++) {
		ips[i] = atoi(str_ip);
		ptr = strchr(str_ip, '.');
		if (ptr == NULL) {
			DOCA_LOG_ERR("Wrong format of ip string");
			return DOCA_ERROR_INVALID_VALUE;
		}
		str_ip = ++ptr;
	}
	ips[3] = atoi(ptr);
	*ipv4_addr = BE_IPV4_ADDR(ips[0], ips[1], ips[2], ips[3]);
	return DOCA_SUCCESS;
}

doca_error_t parse_protocol_string(const char *protocol_str, enum doca_flow_l4_type_ext *protocol) {
	if (strcmp(protocol_str, "tcp") == 0)
		*protocol = DOCA_FLOW_L4_TYPE_EXT_TCP;
	else if (strcmp(protocol_str, "udp") == 0)
		*protocol = DOCA_FLOW_L4_TYPE_EXT_UDP;
	else {
		DOCA_LOG_ERR("Protocol type %s is not supported", protocol_str);
		return DOCA_ERROR_INVALID_VALUE;
	}
	return DOCA_SUCCESS;
}
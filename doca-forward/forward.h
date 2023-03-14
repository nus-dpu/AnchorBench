#ifndef _FORWARD_H_
#define _FORWARD_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_flow.h>

/* DNS configuration structure */
struct dns_filter_config {
	struct doca_flow_pipe **drop_pipes;		/* Holds ports drop pipes */
	enum dns_type_listing listing_type;		/* Holds dns listing type */
	struct application_dpdk_config *dpdk_cfg;	/* App DPDK configuration struct */
	struct doca_pci_bdf pci_address;		/* RegEx PCI address to use */
};

#endif  /* _FORWARD_H_ */
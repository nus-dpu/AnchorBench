#ifndef _SECURITY_GATEWAY_CORE_H_
#define _SECURITY_GATEWAY_CORE_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_ipsec.h>
#include <doca_flow.h>

#include <samples/common.h>

#define DEFAULT_TIMEOUT_US 10000	/* default timeout for processing entries */
#define MAX_FILE_NAME 255		/* Maximum file name length */
#define SECURED_IDX 0			/* Index for secured network port in ports array */
#define UNSECURED_IDX 1			/* Index for unsecured network port in ports array */

/* Security Gateway offload modes */
enum security_gateway_offload_mode {
	SECURITY_GATEWAY_FULL_OFFLOAD,		/* full offload - use fwd port for hairpin */
	SECURITY_GATEWAY_PARTIAL_OFFLOAD,	/* partial offload - process the packets in the application */
};

/* Security Gateway configuration structure */
struct security_gateway_config {
	enum security_gateway_offload_mode mode;	/* application offload mode */
	struct doca_pci_bdf secured_pci_addr;		/* device PCI for secured port */
	struct doca_pci_bdf unsecured_pci_addr;		/* device PCI for unsecured port */
	struct doca_dev *secured_dev;			/* DOCA device for secured network */
	struct doca_dev *unsecured_dev;			/* DOCA device for unsecured network */
	char json_path[MAX_FILE_NAME];			/* Path to the JSON file with rules */
};

/* Security Gateway mapping between dpdk and doca flow port */
struct security_gateway_ports_map {
	struct doca_flow_port *port;	/* doca flow port pointer */
	int port_id;			/* dpdk port ID */
};

/* encryption rule struct */
struct encrypt_rule {
	uint8_t protocol;		/* protocol */
	doca_be32_t src_ip;		/* source IP */
	doca_be32_t dst_ip;		/* destination IP */
	int src_port;			/* source port */
	int dst_port;			/* destination port */
	doca_be32_t encap_dst_ip;	/* destination IP */
	doca_be32_t esp_spi;		/* ipsec session parameter index */
};

/* decryption rule struct */
struct decrypt_rule {
	doca_be32_t dst_ip;	/* destination IP */
	doca_be32_t esp_spi;	/* ipsec session parameter index */
};

/* core context struct */
struct security_gateway_core_ctx {
	uint16_t queue_id;	/* core queue ID */
	uint8_t nb_ports;	/* application number of ports */
};

/*
 * Initialize dpdk ports and queues
 *
 * @app_dpdk_config [in/out]: application dpdk config struct
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t dpdk_queues_and_ports_init(struct application_dpdk_config *app_dpdk_config);

/*
 * Open DOCA devices according to the pci-address input and probe dpdk ports
 *
 * @app_cfg [in/out]: application configuration structure
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t security_gateway_init_devices(struct security_gateway_config *app_cfg);

/*
 * Initalized DOCA Flow library and start DOCA Flow ports
 *
 * @app_cfg [in]: application configuration structure
 * @ports [out]: initalized DOCA Flow ports
 * @return: 0 on success, negative value otherwise
 */
int security_gateway_init_doca_flow(struct security_gateway_config *app_cfg, struct security_gateway_ports_map *ports[]);

/*
 * destroy DOCA Flow resources
 *
 * @nb_ports [in]: number of ports to destroy
 * @ports [in]: initalized DOCA Flow ports
 */
void doca_flow_cleanup(int nb_ports, struct security_gateway_ports_map *ports[]);

/*
 * Create encrypt pipe and entries according to the parsed rules
 *
 * @ports [in]: array of struct security_gateway_ports_map
 * @rules [in]: array of parsed rules to insert
 * @nb_rules [in]: number of rules in the array
 * @sa [in]: crypto object handle (IPsec offload object)
 * @mode [in]: application running mode - full offload / partial offload
 * @nb_queues [in]: number of doca flow queues for RSS
 * @return: 0 on success and negative value otherwise
 */
int security_gateway_insert_encrypt_rules(struct security_gateway_ports_map *ports[], struct encrypt_rule *rules,
					  int nb_rules, struct doca_ipsec_sa *sa, enum security_gateway_offload_mode mode, int nb_queues);

/*
 * Create decrypt pipe and entries according to the parsed rules
 *
 * @port [in]: secured network port pointer
 * @rules [in]: array of parsed rules to insert
 * @nb_rules [in]: number of rules in the array
 * @nb_encrypt_rules [in]: number of rules in the encryption pipe
 * @sa [in]: crypto object handle (IPsec offload object)
 * @mode [in]: application running mode - full offload / partial offload
 * @nb_queues [in]: number of doca flow queues for RSS
 * @return: 0 on success and negative value otherwise
 */
int security_gateway_insert_decrypt_rules(struct security_gateway_ports_map *port, struct decrypt_rule *rules,
					  int nb_rules, int nb_encrypt_rules, struct doca_ipsec_sa *sa,
					  enum security_gateway_offload_mode mode, int nb_queues);

/*
 * Initialized DOCA IPSEC library, and send create SA job
 *
 * @app_cfg [in]: application configuration structure
 * @direction [in]: DOCA_IPSEC_DIRECTION_INGRESS_DECRYPT / DOCA_IPSEC_DIRECTION_EGRESS_ENCRYPT
 * @sa [out]: created crypto sa object
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t security_gateway_create_ipsec_sa(struct security_gateway_config *app_cfg, enum doca_ipsec_direction direction,
					      struct doca_ipsec_sa **sa);

/*
 * Wait in a loop to the incoming traffic, each core will receive packets from a dedicated queue
 *
 * @app_cfg [in]: application configuration structure
 * @dpdk_config [in]: DPDK configuration structure
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t security_gateway_wait_for_traffic(struct security_gateway_config *app_cfg, struct application_dpdk_config *dpdk_config);

/*
 * Parse the json input file and store the parsed rules values in rules array
 *
 * @file_path [in]: json file path with 5 tuple rules to add
 * @nb_encrypt_rules [out]: pointer to the number of encrypt rules in the file
 * @encrypt_rules [out]: pointer to array of initalized encrypt rules
 * @nb_decrypt_rules [out]: pointer to the number of decrypt rules in the file
 * @decrypt_rules [out]: pointer to array of initalized decrypt rules
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t security_gateway_parse_rules(char *file_path, int *nb_encrypt_rules, struct encrypt_rule **encrypt_rules,
					  int *nb_decrypt_rules, struct decrypt_rule **decrypt_rules);

/*
 * Register the command line parameters for the security gateway filter application
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t register_security_gateway_params(void);

#endif  /* _SECURITY_GATEWAY_CORE_H_ */
#include "sc_global.h"
#include "sc_utils.h"
#include "sc_log.h"
#include "sc_doca_utils.h"

#if defined(SC_HAS_DOCA)


/* ================= DOCA core object operation ================ */

/*!
 * \brief   initialize all necessary doca object of  the specified resources
 * \param   mmap    	the allocated doca memery map
 * \param   dev			the doca device instance
 * \param	buf_inv		the allocated doca buffer inventory
 * \param	ctx			the doca context
 * \param	workq		the allocated work queue
 * \param	extensions	?
 * \param	workq_depth	depth of the allocated work queue
 * \param	max_chunks	maximum number of memory chunks
 * \return  zero for successfully initialization
 */
int sc_doca_util_init_core_objects(
		struct doca_mmap **mmap,
		struct doca_dev *dev,
		struct doca_buf_inventory **buf_inv,
		struct doca_ctx *ctx,
		struct doca_workq **workq,
		uint32_t extensions,
		uint32_t workq_depth,
		uint32_t max_chunks
){
	int result = SC_SUCCESS;
	doca_error_t doca_result;
	struct doca_workq *_workq;

	/* allocate doca memory map */
	doca_result = doca_mmap_create(NULL, mmap);
	if (doca_result != DOCA_SUCCESS) {
		SC_ERROR_DETAILS("unable to create mmap: %s", doca_get_error_string(doca_result));
		result = SC_ERROR_INTERNAL;
		goto init_core_objects_exit;
	}

	/* create doca buffer inventory */
	doca_result = doca_buf_inventory_create(NULL, max_chunks, extensions, buf_inv);
	if (doca_result != DOCA_SUCCESS) {
		SC_ERROR_DETAILS("unable to create buffer inventory: %s", 
			doca_get_error_string(doca_result));
		result = SC_ERROR_INTERNAL;
		goto destory_doca_mmap;
	}	

	/* set the maximum number of chunks */
	doca_result = doca_mmap_set_max_num_chunks(*mmap, max_chunks);
	if (doca_result != DOCA_SUCCESS) {
		SC_ERROR_DETAILS("unable to set memory map nb chunks: %s",
			doca_get_error_string(doca_result));
		result = SC_ERROR_INTERNAL;
		goto destory_doca_buf_inv;
	}

	/* start doca memory map */
	doca_result = doca_mmap_start(*mmap);
	if (doca_result != DOCA_SUCCESS) {
		SC_ERROR_DETAILS("unable to start memory map: %s",
			doca_get_error_string(doca_result));
		result = SC_ERROR_INTERNAL;
		goto destory_doca_buf_inv;
	}
    
	/* add device to the allocated memory map */
	doca_result = doca_mmap_dev_add(*mmap, dev);
	if (doca_result != DOCA_SUCCESS) {
		SC_ERROR_DETAILS("unable to add device to mmap: %s",
			doca_get_error_string(doca_result));
		result = SC_ERROR_INTERNAL;
		goto destory_doca_buf_inv;
	}

	/* start the buffer inventory */
	doca_result = doca_buf_inventory_start(*buf_inv);
	if (doca_result != DOCA_SUCCESS) {
		SC_ERROR_DETAILS("unable to start buffer inventory: %s",
			doca_get_error_string(doca_result));
		result = SC_ERROR_INTERNAL;
		goto destory_doca_buf_inv;
	}

	/* add device to the context */
	doca_result = doca_ctx_dev_add(ctx, dev);
	if (doca_result != DOCA_SUCCESS) {
		SC_ERROR_DETAILS("unable to register device with lib context: %s",
			doca_get_error_string(doca_result));
		result = SC_ERROR_INTERNAL;
		goto destory_doca_buf_inv;
	}

	/* start the context */
	doca_result = doca_ctx_start(ctx);
	if (doca_result != DOCA_SUCCESS) {
		SC_ERROR_DETAILS("unable to start lib context: %s",
			doca_get_error_string(doca_result));
		result = SC_ERROR_INTERNAL;
		goto remove_ctx_dev;
	}

	/* create work queue */
	doca_result = doca_workq_create(workq_depth, workq);
	if (doca_result != DOCA_SUCCESS) {
		SC_ERROR_DETAILS("unable to create work queue: %s",
			doca_get_error_string(doca_result));
		result = SC_ERROR_INTERNAL;
		goto remove_ctx_dev;
	}

	/* add work queue to the context */
	doca_result = doca_ctx_workq_add(ctx, *workq);
	if (doca_result != DOCA_SUCCESS) {
		SC_ERROR_DETAILS("unable to register work queue with context: %s", 
			doca_get_error_string(doca_result));
		result = SC_ERROR_INTERNAL;
		goto destory_workq;
	}

	goto init_core_objects_exit;

destory_workq:
	doca_workq_destroy(*workq);
	*workq = NULL;

remove_ctx_dev:
	doca_ctx_dev_rm(ctx, dev);

destory_doca_buf_inv:
	doca_buf_inventory_destroy(*buf_inv);

destory_doca_mmap:
	doca_mmap_destroy(*mmap);

init_core_objects_exit:
	return result;
}

/*!
 * \brief   destory all doca objects of the specified resources
 * \param   mmap    	the allocated doca memery map
 * \param   dev			the doca device instance
 * \param	buf_inv		the allocated doca buffer inventory
 * \param	ctx			the doca context
 * \param	workq		the allocated work queue
 * \return  zero for successfully initialization
 */
int sc_doca_util_destory_core_objects(
		struct doca_mmap **mmap,
		struct doca_dev **dev,
		struct doca_buf_inventory **buf_inv,
		struct doca_ctx *ctx,
		struct doca_workq **workq
){
	int result = SC_SUCCESS;
	doca_error_t doca_result;

	/* release work queue */
	if(*workq != NULL){
		doca_result = doca_ctx_workq_rm(ctx, *workq);
		if(doca_result != DOCA_SUCCESS){
			SC_ERROR_DETAILS("failed to remove work queue from ctx: %s", 
				doca_get_error_string(doca_result));
			result = SC_ERROR_INTERNAL;
		}
		doca_result = doca_workq_destroy(*workq);
		if (doca_result != DOCA_SUCCESS) {
			SC_ERROR_DETAILS("failed to destroy work queue: %s", 
				doca_get_error_string(doca_result));
			result = SC_ERROR_INTERNAL;
		}
		*workq = NULL;
	}

	/* release buffer inventory */
	if(*buf_inv != NULL){
		doca_result = doca_buf_inventory_destroy(*buf_inv);
		if (doca_result != DOCA_SUCCESS) {
			SC_ERROR_DETAILS("failed to destroy buf inventory: %s", 
				doca_get_error_string(doca_result));
			result = SC_ERROR_INTERNAL;
		}
		*buf_inv = NULL;
	}

	/* release memory map */
	if (*mmap != NULL) {
		doca_result = doca_mmap_dev_rm(*mmap, *dev);
		if (doca_result != DOCA_SUCCESS) {
			SC_ERROR_DETAILS("failed to remove device from mmap: %s", 
				doca_get_error_string(doca_result));
		}
		doca_result = doca_mmap_destroy(*mmap);
		if (doca_result != DOCA_SUCCESS) {
			SC_ERROR_DETAILS("failed to destroy mmap: %s",
				doca_get_error_string(doca_result));
			result = SC_ERROR_INTERNAL;
		}
		*mmap = NULL;
	}

	/* release doca device from context */
	if (ctx != NULL) {
		doca_result = doca_ctx_stop(ctx);
		if (doca_result != DOCA_SUCCESS) {
			SC_ERROR_DETAILS("unable to stop context: %s", 
				doca_get_error_string(doca_result));
			result = SC_ERROR_INTERNAL;
		}
		doca_result = doca_ctx_dev_rm(ctx, *dev);
		if (doca_result != DOCA_SUCCESS) {
			SC_ERROR_DETAILS("failed to remove device from ctx: %s",
				doca_get_error_string(doca_result));
			result = SC_ERROR_INTERNAL;
		}
	}

	if (*dev != NULL) {
		doca_result = doca_dev_close(*dev);
		if (doca_result != DOCA_SUCCESS) {
			SC_ERROR_DETAILS("Failed to close device: %s",
				doca_get_error_string(doca_result));
			result = SC_ERROR_INTERNAL;
		}
		*dev = NULL;
	}

	return result;
}

/* =============================================================== */





/* ==================== DOCA device operation ==================== */

/*!
 * \brief   parse given pci address into doca pci bus-device-function tuple
 * \param   pci_addr    the given pci address
 * \param   out_bdf     the parsed bus-device-function tuple
 * \return  zero for successfully initialization
 */
int sc_doca_util_parse_pci_addr(char const *pci_addr, struct doca_pci_bdf *out_bdf){
    /* 11111111_11111111_11111111_00000000 */
    unsigned int bus_bitmask = 0xFFFFFF00;
    /* 11111111_11111111_11111111_11100000 */
	unsigned int dev_bitmask = 0xFFFFFFE0;
    /* 11111111_11111111_11111111_11111000 */
	unsigned int func_bitmask = 0xFFFFFFF8;
    uint32_t tmpu;
	char tmps[4];

    if (pci_addr == NULL || strlen(pci_addr) != 7 || pci_addr[2] != ':' || pci_addr[5] != '.'){
        SC_ERROR_DETAILS("failed to parse pci address string, please check the given format");
        return SC_ERROR_INVALID_VALUE;
    }
    tmps[0] = pci_addr[0];
	tmps[1] = pci_addr[1];
	tmps[2] = '\0';
	tmpu = strtoul(tmps, NULL, 16);
	if ((tmpu & bus_bitmask) != 0){
        SC_ERROR_DETAILS("failed to parse bus info of the given pci address");
        return SC_ERROR_INVALID_VALUE;
    }
	out_bdf->bus = tmpu;

	tmps[0] = pci_addr[3];
	tmps[1] = pci_addr[4];
	tmps[2] = '\0';
	tmpu = strtoul(tmps, NULL, 16);
	if ((tmpu & dev_bitmask) != 0){
        SC_ERROR_DETAILS("failed to parse device info of the given pci address");
        return SC_ERROR_INVALID_VALUE;
    }
	out_bdf->device = tmpu;

	tmps[0] = pci_addr[6];
	tmps[1] = '\0';
	tmpu = strtoul(tmps, NULL, 16);
	if ((tmpu & func_bitmask) != 0){
        SC_ERROR_DETAILS("failed to parse function info of the given pci address");
        return SC_ERROR_INVALID_VALUE;
    }
	out_bdf->function = tmpu;

	return SC_SUCCESS;
}

/*!
 * \brief   open doca device based on given pci address
 * \param   value  	the given pci address
 * \param   func	function to check if a given device is capable of executing some job
 * \param	retval	actual return value
 * \return  zero for successfully openning
 */
int sc_doca_util_open_doca_device_with_pci(
		const struct doca_pci_bdf *value, jobs_check func, struct doca_dev **retval){
	struct doca_devinfo **dev_list;
	uint32_t nb_devs;
	struct doca_pci_bdf buf = {};
	int doca_result, result = SC_SUCCESS;
	size_t i;

	*retval = NULL;

	doca_result = doca_devinfo_list_create(&dev_list, &nb_devs);
	if (doca_result != DOCA_SUCCESS) {
		SC_ERROR_DETAILS("failed to load doca devices list: %s",
		 	doca_get_error_string(doca_result));
		result = SC_ERROR_INTERNAL;
		goto open_doca_device_exit;
	}

	for (i = 0; i < nb_devs; i++) {
		doca_result = doca_devinfo_get_pci_addr(dev_list[i], &buf);
		if (doca_result == DOCA_SUCCESS && buf.raw == value->raw) {
			/* execute job check function if necessary */
			if (func != NULL){
				if(SC_SUCCESS != func(dev_list[i])){
					SC_WARNING("failed to execute jobs check function for %u:%u.%u",
						buf.bus, buf.device, buf.function);
					continue;
				}
			}

			/* open doca device */
			doca_result = doca_dev_open(dev_list[i], retval);
			if(doca_result == DOCA_SUCCESS){
				doca_devinfo_list_destroy(dev_list);
				goto open_doca_device_exit;
			}
		}
	}

	SC_ERROR_DETAILS("matching pci device %u:%u.%u not found",
		value->bus, value->device, value->function);
	result = SC_ERROR_NOT_EXIST;
	doca_devinfo_list_destroy(dev_list);

open_doca_device_exit:
	return result;
}

/* =============================================================== */

#endif // SC_HAS_DOCA
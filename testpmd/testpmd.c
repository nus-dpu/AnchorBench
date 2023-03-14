#include <stdint.h>
#include <stdio.h>

int main(int argc, char **argv) {
	uint32_t i;
	int32_t ret;

	/* initialize EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		return -1;
    }

	argc -= ret;
	argv += ret;

	printf(">>> Packet Burst %d, RX Desc %d, TX Desc %d, mbufs/port %d, mbuf cache %d\n",
			DEFAULT_PKT_BURST, DEFAULT_RX_DESC, DEFAULT_TX_DESC, MAX_MBUFS_PER_PORT, MBUF_CACHE_SIZE);

	/* Configure and initialize the ports */
	pktgen_config_ports();

	/* launch per-lcore init on every lcore except initial and initial + 1 lcores */
	ret = rte_eal_mp_remote_launch(pktgen_launch_one_lcore, NULL, SKIP_MAIN);
	if (ret != 0) {
		printf("Failed to start lcore %d, return %d\n", i, ret);
	}

	rte_delay_ms(250);	/* Wait for the lcores to start up. */

	/* Wait for all of the cores to stop running and exit. */
	rte_eal_mp_wait_lcore();

	RTE_ETH_FOREACH_DEV(i) {
		rte_eth_dev_stop(i);
		rte_delay_ms(100);
	}

	return 0;
}

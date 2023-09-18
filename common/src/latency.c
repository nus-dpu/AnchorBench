#include <stdio.h>

#include "latency.h"

__thread int nr_latency = 0;
__thread bool start_lat_record = false;
__thread struct lat_info * latency;

void output_latency(char * name) {
    /* Discard first 15% latency */
	FILE * output_fp;
    int lat_start = (int)(DISCARD_RATE * nr_latency);

	output_fp = fopen(name, "w");
	if (!output_fp) {
		printf("Error opening latency output file!\n");
		return NULL;
	}

	for (int i = lat_start; i < nr_latency; i++) {
		fprintf(output_fp, "%lu\t%lu\t%lu\n", latency[i].start, latency[i].end, latency[i].end - latency[i].start);
	}

	fclose(output_fp);
}
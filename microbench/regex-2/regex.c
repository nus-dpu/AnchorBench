#include "regex.h"

DOCA_LOG_REGISTER(REGEX::CORE);



int regex_work_lcore(void * arg) {
	doca_error_t result;
	struct regex_ctx * rgx_ctx = (struct regex_ctx *)arg;

    regex_init_lcore(rgx_ctx);

    printf("CPU %02d| initialization done!\n", sched_getcpu());

    return 0;
}
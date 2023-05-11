#include "regex.h"

struct regex_config cfg;
pthread_barrier_t barrier;

static int regex_parse_args(int argc, char ** argv) {
	int opt, option_index, ret;
	double rate;
	static struct option lgopts[] = {
		{"crc-strip", 0, 0, 0},
		{NULL, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "r:d:h", lgopts, &option_index)) != EOF)
		switch (opt) {
		case 'r':	/* RegEx rultes */
			// ret = read_file(optarg, &rules_file_data, &rules_file_size);
			// if (ret == -1) {
			// 	printf("invalid RegEx rules\n");
			// }
			// parse_file_by_line(rules_file_data, rules_file_size);
			char *data_path = (char *)optarg;
			strlcpy(cfg.data, data_path, MAX_FILE_NAME);
			break;

		case 'd':	/* Data file to match cycles */
			char *rule_path = (char *)optarg;
			strlcpy(cfg.rule, rule_path, MAX_FILE_NAME);
			break;

		case 'h':	/* print out the help message */
			// pktgen_usage(prgname);
			return -1;

		case 0:	/* crc-strip for all ports */
			break;
		default:
			return -1;
		}
    return 0;
}

int main(int argc, char **argv) {
	int ret;
    pthread_t pids[MAX_NR_CORE];
    pthread_attr_t pattr;
    cpu_set_t cpu;

	ret = regex_parse_args(argc, argv);

    ret = pthread_attr_init(&pattr);
    if (ret != 0) {
        printf("pthread_attr_init failed!(err: %d)\n", errno);
    }

	pthread_barrier_init(&barrier, NULL, cfg.nr_core);

    for (int i = 0; i < cfg.nr_core; i++) {
        CPU_ZERO(&cpu);
        CPU_SET(i, &cpu);

        /* The pthread_create() call stores the thread ID into
            corresponding element of tinfo[]. */

        ret = pthread_attr_setaffinity_np(&pattr, sizeof(cpu_set_t), &cpu);
        if (ret != 0) {
            printf("pthread_attr_setaffinity_np failed!(err: %d)\n", errno);
        }

        ret = pthread_create(&pids[i], &pattr, &regex_work_lcore, NULL);
        if (ret != 0) {
            printf("pthread_create failed!(err: %d)\n", errno);
        }
    }

	for (int i = 0; i < cfg.nr_core; i++) {
		ret = pthread_join(pids[i], NULL);
        if (ret != 0) {
            printf("pthread_join failed!(err: %d)\n", errno);
        }
	}

    pthread_barrier_destroy(&barrier);

	return EXIT_SUCCESS;
}
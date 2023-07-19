/*
 * kernel/printk.c
 *
 * Print out log information in kernel.
 */
#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>

#define MAX_LOG_LEN	1024
/**
 * printk - print out information on specific core
*/
int printk(const char *fmt, ...) {
    va_list ptr;
	char buf[MAX_LOG_LEN];
	time_t ts;
	off_t off = 0;

	snprintf(buf, 9, "CPU %02d| ", sched_getcpu());
	off = strlen(buf);

    time(&ts);
	off += strftime(buf + off, 32, "%H:%M:%S ", localtime(&ts));

	va_start(ptr, fmt);
	vsnprintf(buf + off, MAX_LOG_LEN - off, fmt, ptr);
	va_end(ptr);

	printf("%s", buf);

	return 0;
}

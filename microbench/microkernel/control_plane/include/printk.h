#ifndef _KERN_H_
#define _KERN_H_

#include <stdio.h>
#include <errno.h>
#include <string.h>

#define ESC "\033["
#define RESET "\033[m"

#define LIGHT_BLUE_BKG	"48;5;33m"
#define LIGHT_RED_BKG	"48;5;196m"
#define GREEN_BKG		"48;5;40m"

#define WHITE		"38;5;231m"
#define YELLOW		"38;5;226m"
#define GREEN		"38;5;40m"
#define LIGHT_RED 	"38;5;196m"

#define BOLD	"\e[1m"
#define OFF		"\e[m"

#define KERN_SOH	"\001"		/* ASCII Start Of Header */

#define KERN_EMERG	KERN_SOH ESC LIGHT_RED_BKG BOLD "<0>" RESET	/* system is unusable */
#define KERN_ALERT	KERN_SOH ESC LIGHT_RED_BKG "<1>" RESET	/* action must be taken immediately */
#define KERN_CRIT	KERN_SOH ESC LIGHT_RED BOLD "<2>" RESET	/* critical conditions */
#define KERN_ERR	KERN_SOH ESC LIGHT_RED "<3>" RESET	/* error conditions */
#define KERN_WARNING	KERN_SOH ESC YELLOW BOLD "<4>" RESET	/* warning conditions */
#define KERN_NOTICE	KERN_SOH ESC LIGHT_GREEN_BKG BOLD "<5>" RESET	/* normal but significant condition */
#define KERN_INFO	KERN_SOH ESC GREEN BOLD "<6>" RESET	/* informational */
#define KERN_DEBUG	KERN_SOH ESC LIGHT_BLUE_BKG "<7>" RESET	/* debug-level messages */

#ifndef pr_fmt
#define pr_fmt(fmt) " "fmt
#endif

extern int printk(const char *fmt, ...);

/*
 * Dummy printk for disabled debugging statements to use whilst maintaining
 * gcc's format checking.
 */
#define no_printk(fmt, ...)				\
({							\
	if (0)						\
		printk(fmt, ##__VA_ARGS__);		\
	0;						\
})

/*
 * These can be used to print at the various printk levels.
 * All of these will print unconditionally, although note that pr_debug()
 * and other debug macros are compiled out unless either DEBUG is defined
 * or CONFIG_DYNAMIC_DEBUG is set.
 */
#define pr_emerg(fmt, ...) \
	printk(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert(fmt, ...) \
	printk(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit(fmt, ...) \
	printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err(fmt, ...) \
	printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warning(fmt, ...) \
	printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn pr_warning
#define pr_notice(fmt, ...) \
	printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info(fmt, ...) \
	printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)

#ifdef DEBUG
#define pr_devel(fmt, ...) \
	printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#else
#define pr_devel(fmt, ...) \
	no_printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#endif

#ifdef DEBUG
#define pr_devel(fmt, ...) \
	printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug(debug, fmt, ...)	\
	if (debug && DBG_ON) {	\
		printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__);	\
	}
#else
#define pr_devel(fmt, ...) \
	no_printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug(debug, fmt, ...)	do {} while (0)
#endif

#endif  /* _KERN_H_ */
#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/**
 * Trim a set of characters like "[]" or "{}" from the start and end of string.
 *
 * @param str
 *   A null terminated string to be trimmed.
 * @param set
 *   The <set> string is a set of two character values to be removed from the
 *   <str>. Removes only one set at a time, if you have more then one set to
 *   remove then you must call the routine for each set. The <set> string must
 *   be two characters and can be any characters you
 *   want to call a set.
 * @return
 *   Pointer to the trimmed string or NULL on error
 */
static __inline__ char * pg_strtrimset(char * str, const char * set) {
	int len;

	len = strlen(set);
	if ((len == 0) || (len & 1)) {
		return NULL;
    }

	for (; set && (set[0] != '\0'); set += 2) {
		if (*str != *set) {
			continue;
        }

		if (*str == *set++) {
			str++;
        }

		len = strlen(str);
		if (len && (str[len - 1] == *set)) {
			str[len - 1] = '\0';
        }
	}
	return str;
}

uint32_t pg_strparse(char * str, const char * delim, char ** entries, uint32_t max_entries);

char * pg_strccpy(char * t, char * f, const char * str);

#endif  /* _UTILS_H_ */
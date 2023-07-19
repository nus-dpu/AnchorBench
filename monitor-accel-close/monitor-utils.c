#include <rte_config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "monitor-utils.h"

#define MAX_PARSE_SIZE      256

/******************************************************************************
 * pg_strtrim  - Remove leading and trailing white space from a string.
 *
 * SYNOPSIS
 * char * pg_strtrim
 *     (
 *     char *    str
 *     )
 *
 * DESCRIPTION
 * Remove leading and trailing white space from a string.
 *
 * RETURNS: pointer to the trimmed string or NULL <str> is Null.
 *
 * ERRNO: N/A
 *
 * \NOMANUAL
 */
static char *
_strtrim(char *str)
{
	char      *p;
	int len;

	if ( (str != NULL) && (len = strlen(str)) ) {
		/* skip white spaces at the front of the string */
		for (; *str != 0; str++)
			if ( (*str != ' ') && (*str != '\t') &&
			     (*str != '\r') && (*str != '\n') )
				break;

		len = strlen(str);
		if (len == 0)
			return str;

		/* Trim trailing characters */
		for (p = &str[len - 1]; p > str; p--) {
			if ( (*p != ' ') && (*p != '\t') && (*p != '\r') &&
			     (*p != '\n') )
				break;
			*p = '\0';
		}
	}
	return str;
}

uint32_t
pg_strparse(char *str, const char *delim, char **entries, uint32_t max_entries)
{
	uint32_t i;
	char      *saved;

	if ( (str == NULL) || (delim == NULL) || (entries == NULL) ||
	     (max_entries == 0) )
		return 0;

	memset(entries, '\0', (sizeof(char *) * max_entries));

	for (i = 0; i < max_entries; i++) {
		entries[i] = strtok_r(str, delim, &saved);
		str = NULL;
		if (entries[i] == NULL)	/* We are done. */
			break;

		entries[i] = _strtrim(entries[i]);
	}

	return i;
}

static uint32_t
skip_lst(char f, const char *lst)
{
	for (; *lst != '\n'; lst++)
		if (f == *lst)
			return 1;
	return 0;
}

char *
pg_strccpy(char *t, char *f, const char *lst)
{
	if ( (t == NULL) || (f == NULL) )
		return NULL;

	*t = '\0';
	if (*f == '\0')
		return t;

	while (*f != '\0') {
		if (skip_lst(*f, lst) )
			f++;
		else
			*t++ = *f++;
	}
	*t = '\0';
	return t;
}

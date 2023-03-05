#ifndef _SC_UTILS_H_
#define _SC_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

#include "sc_global.h"

/*!
 * \brief all return status
 */
enum {
    SC_SUCCESS = 0,
    SC_ERROR_MEMORY,
    SC_ERROR_NOT_EXIST,
    SC_ERROR_INTERNAL,
    SC_ERROR_INVALID_VALUE,
    SC_ERROR_NOT_IMPLEMENTED
};

/* core operation */
int sc_util_stick_this_thread_to_core(uint32_t core_id);
int sc_util_check_core_id(uint32_t core_id);

/* file operation */
int sc_util_parse_config(FILE* fp, struct sc_config* sc_config, 
    int (*parse_kv_pair)(char* key, char *value, struct sc_config* sc_config));

/* string operation */
#define XSTR(x) STR(x)
#define STR(x) #x
char* sc_util_del_left_trim(char *str);
char* sc_util_del_both_trim(char *str);
void sc_util_del_change_line(char *str);
int sc_util_atoui_16(char *in, uint16_t *out);
int sc_util_atoui_32(char *in, uint32_t *out);

/* random operation */
uint32_t sc_util_random_unsigned_int32();
uint64_t random_unsigned_int64();

#endif
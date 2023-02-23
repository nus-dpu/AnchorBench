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
    SC_ERROR_INPUT,
    SC_ERROR_NOT_IMPLEMENTED
};

/* core operation */
int stick_this_thread_to_core(uint32_t core_id);
int check_core_id(uint32_t core_id);

/* file operation */
int parse_config(FILE* fp, struct sc_config* sc_config, 
    int (*parse_kv_pair)(char* key, char *value, struct sc_config* sc_config));

/* string operation */
#define XSTR(x) STR(x)
#define STR(x) #x
char* del_left_trim(char *str);
char* del_both_trim(char *str);
void del_change_line(char *str);
int atoui_16(char *in, uint16_t *out);
int atoui_32(char *in, uint32_t *out);

/* random operation */
uint32_t random_unsigned_int32();
uint64_t random_unsigned_int64();

#endif
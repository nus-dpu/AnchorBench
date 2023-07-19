#ifndef _TYPES_H_
#define _TYPES_H_

#include "bitops.h"

#define DECLARE_BITMAP(name, bits)  unsigned long name[BITS_TO_LONGS(bits)]

typedef unsigned __poll_t;

#endif /* _TYPES_H_ */
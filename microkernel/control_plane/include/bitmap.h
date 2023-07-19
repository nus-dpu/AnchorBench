#ifndef _BITMAP_H_
#define _BITMAP_H_

#include <string.h>

#include "bitops.h"

#define small_const_nbits(nbits) \
	(__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG && (nbits) > 0)

#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))

extern int __bitmap_weight(const unsigned long *bitmap, unsigned int bits);

static inline void bitmap_copy(unsigned long * dst, const unsigned long * src, unsigned int nbits) {
	unsigned int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
	memcpy(dst, src, len);
}

static inline int bitmap_and(unsigned long * dst, const unsigned long * src1, const unsigned long * src2, unsigned int nbits) {
	return (*dst = *src1 & *src2 & BITMAP_LAST_WORD_MASK(nbits)) != 0;
}

#endif  /* _BITMAP_H_ */
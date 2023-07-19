#include <stdio.h>

#include "bitops.h"
#include "types.h"

#ifndef max
#define max(x, y) ({				\
	typeof(x) _x = (x);			\
	typeof(y) _y = (y);			\
	_x > _y ? _x : _y; })
#endif

#ifndef min
#define min(x, y) ({				\
	typeof(x) _x = (x);			\
	typeof(y) _y = (y);			\
	_x < _y ? _x : _y; })
#endif

static inline unsigned long _find_next_bit(const unsigned long * addr1, const unsigned long * addr2, 
                                    unsigned long nbits, unsigned long start, unsigned long invert) {
    unsigned long tmp, bitmask;
    if (start >= nbits) {
        return nbits;
    }
    
    tmp = *addr1;
    if (addr2) {
        tmp &= (*addr2);
    }

    int offset;

    for (offset = start; offset < nbits; offset++) {
        bitmask = 1UL << offset;

        if ((tmp ^ invert) & bitmask) {
            break;
        }
    }
    
    return (offset < nbits)? offset : nbits;
}

unsigned long find_next_bit(const unsigned long * addr, unsigned long size, unsigned long offset) {
    return _find_next_bit(addr, NULL, size, offset, 0UL);
}

unsigned long find_next_zero_bit(const unsigned long * addr, unsigned long size, unsigned long offset) {
    return _find_next_bit(addr, NULL, size, offset, ~0UL);
}

unsigned long find_first_bit(const unsigned long *addr, unsigned long size) {
	unsigned long idx;

	for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
		if (addr[idx])
			return min(idx * BITS_PER_LONG + __ffs(addr[idx]), size);
	}

	return size;
}
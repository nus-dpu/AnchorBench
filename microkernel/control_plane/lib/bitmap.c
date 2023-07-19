#include "bitmap.h"
#include "bitops.h"

int __bitmap_weight(const unsigned long *bitmap, unsigned int bits) {
	unsigned int k, lim = bits / BITS_PER_LONG;
	int w = 0;

	for (k = 0; k < lim; k++)
		w += hweight_long(bitmap[k]);

	if (bits % BITS_PER_LONG)
		w += hweight_long(bitmap[k] & BITMAP_LAST_WORD_MASK(bits));

	return w;
}

int bitmap_weight(const unsigned long * src, unsigned int nbits) {
	if (small_const_nbits(nbits)) {
		return hweight_long(*src & BITMAP_LAST_WORD_MASK(nbits));
	}
	return __bitmap_weight(src, nbits);
}
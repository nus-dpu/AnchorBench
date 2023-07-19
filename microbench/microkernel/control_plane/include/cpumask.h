#ifndef _CPUMASK_H_
#define _CPUMASK_H_

#include <stdbool.h>

#include "types.h"
#include "bitmap.h"
#include "threads.h"

typedef struct cpumask { DECLARE_BITMAP(bits, NR_CPUS); } cpumask_t;

extern struct cpumask __cpu_possible_mask;
extern struct cpumask __cpu_online_mask;
extern struct cpumask __cpu_present_mask;
extern struct cpumask __cpu_active_mask;

#if NR_CPUS == 1
#define nr_cpu_ids		1U
#else
extern unsigned int nr_cpu_ids;
#endif

extern int __num_online_cpus;

#if NR_CPUS > 1
/**
 * num_online_cpus() - Read the number of online CPUs
 */
static inline unsigned int num_online_cpus(void) {
	return __num_online_cpus;
}
#define num_possible_cpus()	cpumask_weight(cpu_possible_mask)
#define num_present_cpus()	cpumask_weight(cpu_present_mask)
#define num_active_cpus()	cpumask_weight(cpu_active_mask)
#define cpu_online(cpu)		cpumask_test_cpu((cpu), cpu_online_mask)
#define cpu_possible(cpu)	cpumask_test_cpu((cpu), cpu_possible_mask)
#define cpu_present(cpu)	cpumask_test_cpu((cpu), cpu_present_mask)
#define cpu_active(cpu)		cpumask_test_cpu((cpu), cpu_active_mask)
#else
#define num_online_cpus()	1U
#define num_possible_cpus()	1U
#define num_present_cpus()	1U
#define num_active_cpus()	1U
#define cpu_online(cpu)		((cpu) == 0)
#define cpu_possible(cpu)	((cpu) == 0)
#define cpu_present(cpu)	((cpu) == 0)
#define cpu_active(cpu)		((cpu) == 0)
#endif

/**
 *	cpu_possible mask - contains maximum number of CPUs which are possible in the system
 *	Equal to value of the NR_CPUS.
 */
#define cpu_possible_mask ((const struct cpumask *)&__cpu_possible_mask)

/**
 * cpu_present mask - which CPUs are currently plugged in
 */
#define cpu_online_mask   ((const struct cpumask *)&__cpu_online_mask)

/**
 * cpu_online mask - a subset of the cpu_present, indicates CPUs which are available for scheduling
 * A bit from this mask tells to kernel is a processor may be utilized by the kernel.
 */
#define cpu_present_mask  ((const struct cpumask *)&__cpu_present_mask)

/**
 * cpu_active mask - A task may be moved to a certain processor in this mask.
 */
#define cpu_active_mask   ((const struct cpumask *)&__cpu_active_mask)

#define cpumask_bits(maskp) ((maskp)->bits)
#define nr_cpumask_bits ((unsigned int)NR_CPUS)

static inline void bitmap_fill(unsigned long *dst, unsigned int nbits) {
	unsigned int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
	memset(dst, 0xff, len);
}

static inline void bitmap_zero(unsigned long * dst, unsigned int nbits) {
	unsigned int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
	memset(dst, 0, len);
}

/**
 * cpumask_first - get the first cpu in a cpumask
 * @srcp: the cpumask pointer
 *
 * Returns >= nr_cpu_ids if no cpus set.
 */
static inline unsigned int cpumask_first(const struct cpumask *srcp) {
	return find_first_bit(cpumask_bits(srcp), nr_cpumask_bits);
}

#define cpumask_any(srcp) cpumask_first(srcp)

/**
 * cpumask_set_cpu - set a cpu in a cpumask
 * @cpu: cpu number (< nr_cpu_ids)
 * @dstp: the cpumask pointer
 */
static inline void cpumask_set_cpu(unsigned int cpu, struct cpumask * dstp) {
	set_bit(cpu, cpumask_bits(dstp));
}

/**
 * cpumask_setall - set all cpus (< nr_cpu_ids) in a cpumask
 * @dstp: the cpumask pointer
 */
static inline void cpumask_setall(struct cpumask * dstp) {
	bitmap_fill(cpumask_bits(dstp), nr_cpumask_bits);
}

/**
 * cpumask_clear_cpu - clear a cpu in a cpumask
 * @cpu: cpu number (< nr_cpu_ids)
 * @dstp: the cpumask pointer
 */
static inline void cpumask_clear_cpu(int cpu, struct cpumask * dstp) {
	clear_bit(cpu, cpumask_bits(dstp));
}

/**
 * cpumask_clear - clear all cpus (< nr_cpu_ids) in a cpumask
 * @dstp: the cpumask pointer
 */
static inline void cpumask_clear(struct cpumask *dstp) {
	bitmap_zero(cpumask_bits(dstp), nr_cpumask_bits);
}

/**
 * cpumask_copy - *dstp = *srcp
 * @dstp: the result
 * @srcp: the input cpumask
 */
static inline void cpumask_copy(struct cpumask * dstp, const struct cpumask * srcp) {
	bitmap_copy(cpumask_bits(dstp), cpumask_bits(srcp), nr_cpumask_bits);
}

/**
 * cpumask_test_cpu - test for a cpu in a cpumask
 * @cpu: cpu number (< nr_cpu_ids)
 * @cpumask: the cpumask pointer
 *
 * Returns 1 if @cpu is set in @cpumask, else returns 0
 */
static inline int cpumask_test_cpu(int cpu, struct cpumask * cpumask) {
	return test_bit(cpu, cpumask_bits((cpumask)));
}

/**
 * cpumask_and - *dstp = *src1p & *src2p
 * @dstp: the cpumask result
 * @src1p: the first input
 * @src2p: the second input
 *
 * If *@dstp is empty, returns 0, else returns 1
 */
static inline int cpumask_and(struct cpumask * dstp, const struct cpumask * src1p, const struct cpumask * src2p) {
	return bitmap_and(cpumask_bits(dstp), cpumask_bits(src1p),
				       cpumask_bits(src2p), nr_cpumask_bits);
}

static inline void set_cpu_possible(unsigned int cpu, bool possible) {
	if (possible) {
		cpumask_set_cpu(cpu, &__cpu_possible_mask);
    } else {
		cpumask_clear_cpu(cpu, &__cpu_possible_mask);
    }
}

static inline void set_cpu_present(unsigned int cpu, bool present) {
	if (present) {
		cpumask_set_cpu(cpu, &__cpu_present_mask);
	} else {
		cpumask_clear_cpu(cpu, &__cpu_present_mask);
	}
}

static inline void set_cpu_active(unsigned int cpu, bool active) {
	if (active) {
        cpumask_set_cpu(cpu, &__cpu_active_mask);
    } else {
		cpumask_clear_cpu(cpu, &__cpu_active_mask);
    }
}

static inline void set_cpu_online(unsigned int cpu, bool online) {
	if (online) {
        cpumask_set_cpu(cpu, &__cpu_online_mask);
    } else {
		cpumask_clear_cpu(cpu, &__cpu_online_mask);
    }
}

extern int bitmap_weight(const unsigned long * src, unsigned int nbits);

/**
 * cpumask_weight - Count of bits in *srcp
 * @srcp: the cpumask to count bits (< nr_cpu_ids) in.
 */
static inline unsigned int cpumask_weight(const struct cpumask * srcp) {
	return bitmap_weight(cpumask_bits(srcp), nr_cpumask_bits);
}

static inline unsigned int cpumask_next(int n, const struct cpumask * srcp) {
	return find_next_bit(cpumask_bits(srcp), nr_cpumask_bits, n + 1);
}

/**
 * for_each_cpu - iterate over every cpu in a mask
 * @cpu: the (optionally unsigned) integer iterator
 * @mask: the cpumask pointer
 *
 * After the loop, cpu is >= nr_cpu_ids.
 */
#define for_each_cpu(cpu, mask)				\
	for ((cpu) = -1;				\
		(cpu) = cpumask_next((cpu), (mask)),	\
		(cpu) < nr_cpu_ids;)

#define for_each_possible_cpu(cpu) for_each_cpu((cpu), cpu_possible_mask)
#define for_each_online_cpu(cpu)   for_each_cpu((cpu), cpu_online_mask)
#define for_each_present_cpu(cpu)  for_each_cpu((cpu), cpu_present_mask)

#endif  /* _CPUMASK_H_ */
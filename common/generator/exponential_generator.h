#ifndef _EXP_GENERATOR_H_
#define _EXP_GENERATOR_H_

#include "generator.h"

#include <random>

class ExponentialGenerator : public Generator<uint64_t> {
    public:
        ExponentialGenerator(int exp_mean) {
            double mean = (double)exp_mean;
            double dist_lambda = 1 / mean;
            G_ = std::exponential_distribution<>{dist_lambda};
            generator_ = std::default_random_engine{};
        }

        uint64_t Next() {
            return (uint64_t)(ceil(G_(generator_)));
        }

        uint64_t Last() {
            return 0;
        }

    private:  
        std::exponential_distribution<> G_;
        std::default_random_engine generator_;
};

#endif  /* _EXP_GENERATOR_H_ */
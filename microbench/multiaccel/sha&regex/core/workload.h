#ifndef _WORKLOAD_H_
#define _WORKLOAD_H_

#include <vector>
#include <string>
#include "properties.h"
#include "generator.h"
#include "discrete_generator.h"
#include "counter_generator.h"

enum Job {
    REGEX,
    SHA,
};

class Workload {
    static const std::string SHA_INPUT_PROPERTY;
    static const std::string SHA_INPUT_DEFAULT;

    static const std::string REGEX_INPUT_PROPERTY;
    static const std::string REGEX_INPUT_DEFAULT;

    static const std::string REGEX_PROPORTION_PROPERTY;
    static const std::string REGEX_PROPORTION_DEFAULT;

    static const std::string REGEX_PROPORTION_PROPERTY;
    static const std::string REGEX_PROPORTION_DEFAULT;

    virtual Job NextOperation() { return op_chooser_.Next(); }

    virtual void Init(const Properties &p);

    Workload() {}
    ~Workload() {}
  
protected:
    DiscreteGenerator<Job> op_chooser_;
};

#endif  /* _WORKLOAD_H_ */
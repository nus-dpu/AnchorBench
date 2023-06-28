#include "workload.h"

#include <string>

const std::string workload::SHA_INPUT_PROPERTY = "shainput";
const std::string workload::SHA_INPUT_DEFAULT = "sha.dat";

const std::string workload::SHA_PROPORTION_PROPERTY = "shaproportion";
const std::string workload::SHA_PROPORTION_DEFAULT = "0.5";

const std::string workload::REGEX_INPUT_PROPERTY = "regexinput";
const std::string workload::REGEX_INPUT_DEFAULT = "regex.dat";

const std::string workload::REGEX_PROPORTION_PROPERTY = "regexproportion";
const std::string workload::REGEX_PROPORTION_DEFAULT = "0.5";

void Workload::Init(const Properties &p) {
    double sha_proportion = std::stod(p.GetProperty(SHA_PROPORTION_PROPERTY,
                                                    SHA_PROPORTION_DEFAULT));
    double regex_proportion = std::stod(p.GetProperty(REGEX_PROPORTION_PROPERTY,
                                                    REGEX_PROPORTION_DEFAULT));

    if (sha_proportion > 0) {
        op_chooser_.AddValue(SHA, sha_proportion);
    }
    if (regex_proportion > 0) {
        op_chooser_.AddValue(REGEX, regex_proportion);
    }
}
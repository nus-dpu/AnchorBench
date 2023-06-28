#include <string>
#include <iostream>

#include "props.h"
#include "workload.h"

#include "core/workload.h"
#include "core/properties.h"

Properties props;
__thread Workload wl;

int InitProps(char * filename) {
    std::ifstream input(filename);
	try {
		props.Load(input);
	} catch (const std::string &message) {
		std::cout << message << std::endl;
		exit(0);
	}
	input.close();
}

int InitWorkload() {
	wl.Init(props);
}

char * GetSHAInput() {
    std::string name;
    name = props.GetProperty(Workload::SHA_INPUT_PROPERTY, Workload::SHA_INPUT_DEFAULT);
    return (char *)name.c_str();
}

char * GetRegExInput() {
    std::string name;
    name = props.GetProperty(Workload::REGEX_INPUT_PROPERTY, Workload::REGEX_INPUT_DEFAULT);
    return (char *)name.c_str();
}

int GetNextJob() {
    return (int)wl.NextOperation();
}

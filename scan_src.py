'''
argv[1] - app:          application name
argv[2] - has_doca:     whether the doca library is enabled
argv[3] - doca_path:    path to the doca directory
argv[4] - doca_version: version of current used doca
argv[5] - has_cuda:     whether the cuda library is enabled
argv[6] - cuda_path:    path to the cuda directory
'''

import sys
import glob

# add all local source files
sources = glob.glob("./src/*.c") + glob.glob("./src/sc_utils/*.c") + glob.glob("./src/sc_{}/*.c".format(sys.argv[1]))

# optional: add doca source files (i.e. application and sample code)
if(sys.argv[2] == "true" and sys.argv[4][0:3] == '1.5'):
    # sample common utilization code
    sources += glob.glob("{}/samples/*.c".format(sys.argv[3]))
    sources += glob.glob("{}/samples/*/*_common.c".format(sys.argv[3]))
    # application common utillization code
    sources += glob.glob("{}/applications/common/src/*.c".format(sys.argv[3]))
    # exclude gpu related files if cuda isn't enabled
    if(sys.argv[5] != "true"):
        sources.remove("{}/applications/common/src/gpu_init.c".format(sys.argv[3]))

for i in sources:
    print(i)
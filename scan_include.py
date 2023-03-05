'''
argv[1] - project:      project name (abbreviation)
argv[2] - app:          application name
argv[3] - has_doca:     whether the doca library is enabled
argv[4] - doca_path:    path to the doca directory
argv[5] - doca_version: version of current used doca
argv[6] - has_cuda:     whether the cuda library is enabled
argv[7] - cuda_path:    path to the cuda directory
'''

import sys
import glob


# add all local include files
include_dirs = [
    "include",
    "include/{}_utils".format(sys.argv[1]),
    "include/{}_{}".format(sys.argv[1], sys.argv[2])
]

# optional: add doca headers files of applications and samples
if(sys.argv[3] == "true" and sys.argv[5][0:3] == '1.5'):
    include_dirs += [
        # "{}/samples/".format(sys.argv[4]),
        # "{}/samples/doca_apsh".format(sys.argv[4]),
        # "{}/samples/doca_comm_channel".format(sys.argv[4]),
        # "{}/samples/doca_compress".format(sys.argv[4]),
        # "{}/samples/doca_dma".format(sys.argv[4]),
        # "{}/samples/doca_dpi".format(sys.argv[4]),
        # "{}/samples/doca_flow".format(sys.argv[4]),
        # "{}/samples/doca_regex".format(sys.argv[4]),
        # "{}/samples/doca_sha".format(sys.argv[4]),
        # "{}/samples/doca_telemetry".format(sys.argv[4]),
        "{}".format(sys.argv[4])
    ]
    
# optional: add cuda headers files
if(sys.argv[6] == "true"):
    include_dirs += [
        "{}/include".format(sys.argv[7])
    ]

for i in include_dirs:
    print(i)
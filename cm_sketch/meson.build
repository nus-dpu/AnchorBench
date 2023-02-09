# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

project('SHA_CREATE', 'C', 
    # Get version number from file.
	version: run_command(find_program('cat'),
		files('/opt/mellanox/doca/applications/VERSION'), check: true).stdout().strip(),
	license: 'Proprietary',
	default_options: ['buildtype=debug'],
	meson_version: '>= 0.61.2'
)

project_name = 'cm_sketch'

# Comment this line to restore warnings of experimental DOCA features
add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: ['c'])

deps = []
deps += dependency('libdpdk')
# Required for all DOCA programs
deps += dependency('doca-common')
# Library needed for this sample
deps += dependency('doca-sha')
deps += dependency('doca-flow')
# Library used by the main() function
deps += dependency('doca-argp')

inc_dirs  = []
# Common DOCA logic (samples)
inc_dirs += include_directories('./dependencies')
# Common DOCA logic (applications)
inc_dirs += include_directories('./dependencies/application_common/src')
# DOCA Flow logic (samples)
inc_dirs += include_directories('./dependencies/samples/doca_flow')

sources = [
	# The sample itself
	project_name + '_flow.c',
	# Main function for the sample's executable
	project_name + '_main.c',
	# The sample's dpdk utils
	project_name + '_dpdk.c',
	# The sample's params utils
	project_name + '_params.c',
	# The sample's other utils
	project_name + '_utils.c',
	# Common code for all DOCA samples
	'./dependencies/common.c',
    './dependencies/samples/doca_flow/flow_common.c',
	# Common code for all DOCA applications
	'./dependencies/application_common/src/flow_pipes_manager.c',
	'./dependencies/application_common/src/flow_parser.c',
	'./dependencies/application_common/src/utils.c',
    './dependencies/application_common/src/dpdk_utils.c',
	'./dependencies/application_common/src/offload_rules.c',
]

executable(project_name, sources,
	dependencies : deps,
	include_directories: inc_dirs,
	install: false)
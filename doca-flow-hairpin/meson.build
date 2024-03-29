# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

project('dns_filter', 'C', 
    license: 'BSD',
    default_options: ['buildtype=debug'],
	meson_version: '>= 0.51.0'
)

project_name = 'flow_hairpin'

deps = []
deps += dependency('libdpdk')
deps += dependency('json-c')
deps += dependency('doca-argp')
deps += dependency('doca-flow')
deps += dependency('doca-common')

common_path = '../' + 'common'
common_src_path = '../' + 'common/src'

inc_dirs = [
	include_directories(common_src_path),
	include_directories(common_path),
	include_directories('..'),
]

sources = files([
	project_name + '.c',
	project_name + '_core.c',
	common_src_path + '/dpdk_utils.c',
	common_src_path + '/offload_rules.c',
	common_src_path + '/utils.c',
	common_src_path + '/flow_parser.c',
	common_path + '/flow_common.c',
])

# With enabling GPU support, languages variable will contain CUDA language
languages = ['c', 'cpp']

add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: languages)

executable(project_name,
        sources,
        dependencies: deps,
	include_directories : inc_dirs,
        install: false)

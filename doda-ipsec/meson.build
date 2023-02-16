# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

project('ipsec', 'C', 
    license: 'BSD',
    default_options: ['buildtype=debug'],
	meson_version: '>= 0.51.0'
)

project_name = 'security_gateway'

deps = []
deps += dependency('libdpdk')
deps += dependency('doca-argp')
deps += dependency('doca-ipsec')
deps += dependency('doca-flow')
deps += dependency('doca-common')

common_path = 'common'
common_src_path = 'common/src'
common_dir_path = '../' + common_src_path

inc_dirs = [
	include_directories(common_dir_path),
	include_directories('..'),
]

machine_args = []

default_cflags = machine_args
cflags = default_cflags

sources = files(
        project_name + '.c',
        project_name + '_core.c',
	common_dir_path + '/dpdk_utils.c',
	common_dir_path + '/offload_rules.c',
	common_dir_path + '/utils.c',
	common_dir_path + '/flow_parser.c',
	common_path + '/common.c',
)

allow_experimental_apis = true

if allow_experimental_apis
        cflags += '-DALLOW_EXPERIMENTAL_API'
endif

executable(project_name,
        sources,
        dependencies: deps,
	include_directories : inc_dirs,
        c_args: cflags,
        install: false)

# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

project('multiaccel', 'C', 'CPP',
    license: 'BSD',
    default_options: ['buildtype=debug'],
	meson_version: '>= 0.51.0'
)

project_name = 'multiaccel'

add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: ['c','cpp'])

deps = []
deps += dependency('doca-argp')
deps += dependency('doca-common')
deps += dependency('doca-regex')
deps += dependency('doca-sha')
deps += dependency('libbsd')

machine_args = []

default_cflags = machine_args
cflags = default_cflags

core_path = 'core'

inc_dirs = [
	include_directories(core_path),
	include_directories('../'),
]

sources = files(
    project_name + '.cc',
    project_name + '_main.cc',
	'sha_mempool.c',
	'regex_mempool.c',
	core_path + '/workload.cc',
)

executable(project_name,
        sources,
	    include_directories : inc_dirs,
        dependencies: deps,
        c_args: cflags,
        link_args: ['-lpthread'],
        install: false)
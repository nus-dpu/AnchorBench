# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

project('ipsec', 'C', 
    license: 'BSD',
    default_options: ['buildtype=debug'],
	meson_version: '>= 0.51.0'
)

project_name = 'dns-filter'

deps = []
deps += dependency('libdpdk')

machine_args = []

default_cflags = machine_args
cflags = default_cflags

sources = files(
    project_name + '.c',
	project_name + '-port-cfg.c',
	project_name + '-l2p.c',
	project_name + '-utils.c',
)

allow_experimental_apis = true

if allow_experimental_apis
        cflags += '-DALLOW_EXPERIMENTAL_API'
endif

executable(project_name,
        sources,
        dependencies: deps,
        c_args: cflags,
        install: false)
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Mellanox Technologies, Ltd

project('test-flow-perf', 'C', 
    license: 'BSD',
    default_options: ['buildtype=debug'],
	meson_version: '>= 0.51.0'
)

project_name = 'test-flow-perf'

sources = files(
	'actions_gen.c',
	'flow_gen.c',
	'items_gen.c',
	'main.c',
)

deps = []
deps += dependency('libdpdk')
deps += ['ethdev']

machine_args = []
default_cflags = machine_args + ['-DALLOW_EXPERIMENTAL_API']
cflags = default_cflags

executable(project_name,
        sources,
        dependencies: deps,
        c_args: cflags,
        install: false)
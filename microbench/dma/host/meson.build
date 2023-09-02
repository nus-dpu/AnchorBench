# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

project('DMA', 'C',
    # Get version number from file.
	version: run_command(find_program('cat'),
		files('/opt/mellanox/doca/applications/VERSION'), check: true).stdout().strip(),
	license: 'Proprietary',
	default_options: ['buildtype=debug'],
	meson_version: '>= 0.61.2'
)

project_name = 'dma_copy'

add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: ['c'])

deps = []
deps += dependency('doca')

machine_args = []

default_cflags = machine_args
cflags = default_cflags

inc_dirs = [
	include_directories('..'),
]

sources = files(
    project_name + '.c',
    project_name + '_core.c',
    'common.c',
    'utils.c',
    'pack.c',
)

executable(project_name,
        sources,
	    include_directories : inc_dirs,
        dependencies: deps,
        c_args: cflags,
        link_args: ['-lm','-lpthread'],
        install: false)
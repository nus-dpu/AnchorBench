# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

project('firewall', 'C',
    license: 'BSD',
    default_options: ['buildtype=debug'],
	meson_version: '>= 0.51.0'
)

project_name = 'firewall'

add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: ['c'])

deps = []
deps += dependency('doca')
deps += dependency('libbsd')

machine_args = []

default_cflags = machine_args
cflags = default_cflags

common_path = '../common'
common_dir_path = '../' + common_path

inc_dirs = [
	include_directories(common_path),
	include_directories('..'),
]

sources = files(
    project_name + '.c',
)

executable(project_name,
        sources,
	    include_directories : inc_dirs,
        dependencies: deps,
        c_args: cflags,
        link_args: ['-ljson-c'],
        install: false)
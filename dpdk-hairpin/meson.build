# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

project('ipsec', 'C', 
    license: 'BSD',
    default_options: ['buildtype=debug'],
	meson_version: '>= 0.51.0'
)

project_name = 'flow_hairpin'

add_project_arguments('-D ALLOW_EXPERIMENTAL_API', language: ['c'])

deps = []
deps += dependency('libdpdk')

machine_args = []

default_cflags = machine_args
cflags = default_cflags

inc_dirs = [
	include_directories('../'),
]

sources = files(
    project_name + '.c',
)

executable(project_name,
        sources,
        dependencies: deps,
        c_args: cflags,
        install: false)
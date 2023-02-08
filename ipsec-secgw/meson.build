# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

project('ipsec', 'C', 
    license: 'BSD',
    default_options: ['buildtype=debug'],
	meson_version: '>= 0.51.0'
)

project_name = 'ipsec'

deps = []
deps += dependency('libdpdk')

sources = files(
        'esp.c',
        'event_helper.c',
        'flow.c',
        'ipsec.c',
        'ipsec_process.c',
        'ipsec-secgw.c',
        'ipsec_worker.c',
        'parser.c',
        'rt.c',
        'sa.c',
        'sad.c',
        'sp4.c',
        'sp6.c',
)

executable(project_name, sources,
	dependencies : deps,
	install: false)
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

project('ipsec', 'C', 
    license: 'BSD',
    default_options: ['buildtype=debug'],
	meson_version: '>= 0.51.0'
)

project_name = 'dpdk-test'

deps = []
deps += dependency('libdpdk')

machine_args = []

default_cflags = machine_args
cflags = default_cflags

sources = files(
        'commands.c',
        'packet_burst_generator.c',
        'test.c',
        'test_ipsec.c',
        'test_ipsec_perf.c',
        'test_pmd_perf.c',
)

perf_test_names = [
        'ipsec_perf_autotest',
]

allow_experimental_apis = true

if allow_experimental_apis
        cflags += '-DALLOW_EXPERIMENTAL_API'
endif

executable(project_name,
        sources,
        dependencies: deps,
        c_args: cflags,
        install: false)
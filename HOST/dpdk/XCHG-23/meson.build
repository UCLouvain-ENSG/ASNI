#
# Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

project('DPDK_PORT_FORWARD', 'C', 'CPP',
        license: 'Proprietary',
        default_options: ['buildtype=release','-Db_lto=true','c_args=-flto','c_link_args=-flto'],
        meson_version: '>= 0.61.2'
)

# Comment this line to restore warnings of experimental DOCA features
add_project_arguments(language: ['c', 'cpp'])

dependencies = []
# Library used by the main() function
dependencies += dependency('libbsd')
#
#dependencies += dependency('libdpdk', static: true)

pkgconfig = find_program('pkg-config')
cflags_cmd = run_command(pkgconfig, '--cflags', 'libdpdk', check: true)
ldflags_cmd = run_command(pkgconfig, '--static', '--libs', 'libdpdk', check: true)

cflags = cflags_cmd.stdout().split()
ldflags = ldflags_cmd.stdout().split()

srcs = [
        # The sample itself
        'server.c',
        'xchg.c',
	# The dpdk utils (to inititiate the port)
#	'../../../utils/port_init.c',
        '../../../utils/MACaddress.c',
]

inc_dirs  = []
#
inc_dirs += include_directories('../../../utils')

executable('server', srcs,
        dependencies : dependencies,
	include_directories: inc_dirs,
        c_args: cflags, link_args: ldflags,
        install: false)

executable('server-cycles', srcs,
        dependencies : dependencies,
	include_directories: inc_dirs,
        c_args: cflags + ['-DHAVE_CYCLE'], link_args: ldflags,
        install: false)

executable('server-minimal', srcs,
        dependencies : dependencies,
	include_directories: inc_dirs,
        c_args: cflags + ['-DHAVE_MINIMAL'], link_args: ldflags,
        install: false)

executable('server-cycles-minimal', srcs,
        dependencies : dependencies,
	include_directories: inc_dirs,
        c_args: cflags + ['-DHAVE_CYCLE','-DHAVE_MINIMAL'], link_args: ldflags,
        install: false)

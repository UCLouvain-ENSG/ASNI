
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
        default_options: ['buildtype=release'],
        meson_version: '>= 0.61.2'
)

# Comment this line to restore warnings of experimental DOCA features
add_project_arguments(['-ggdb'],language: ['c', 'cpp'])
inc_dirs = []
dependencies = []
# Library used by the main() function
dependencies += dependency('libbsd')
#
dependencies += dependency('libdpdk')

srcs = [
        'server.c',
        '../../../utils/MACaddress.c'
]

inc_dirs = []
inc_dirs += include_directories('../../../utils')

executable('forwarder_asni', srcs,
        dependencies : dependencies,
        install: false,
        c_args: ['-DFAKE_DPDK_DESC_SIZE','-DFAKE_DPDK_MODE_DPDK_ASQ'])

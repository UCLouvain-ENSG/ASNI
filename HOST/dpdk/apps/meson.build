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
add_project_arguments(language: ['c', 'cpp'])

dependencies = []
# Library used by the main() function
dependencies += dependency('libbsd')
#
dependencies += dependency('libdpdk')

srcs = [
        # The sample itself
        'baseline_load_balancer.c',
	# The dpdk utils (to inititiate the port)
#	'../../../utils/port_init.c',
        '../../../utils/MACaddress.c',
        '../../../utils/dpdk_utils2.c',
]

srcs_asq = [
        # The sample itself
        'asq_load_balancer.c',
	# The dpdk utils (to inititiate the port)
#	'../../../utils/port_init.c',
        '../../../utils/MACaddress.c',
        '../../../utils/dpdk_utils2.c',
]

inc_dirs  = []
#
inc_dirs += include_directories('../../../utils')

executable('baseline_load_balancer', srcs,
        dependencies : dependencies,
	include_directories: inc_dirs,
        install: false)


executable('asq_load_balancer', srcs_asq,
        dependencies : dependencies,
	include_directories: inc_dirs,
        install: false)

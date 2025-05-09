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

project('DOCA_SAMPLE', 'C', 'CPP',
	# Get version number from file.
	version: run_command(find_program('cat'),
		files('/opt/mellanox/doca/applications/VERSION'), check: true).stdout().strip(),
	license: 'Proprietary',
	default_options: ['buildtype=release'],
	meson_version: '>= 0.61.2'
)


# Comment this line to restore warnings of experimental DOCA features
add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: ['c', 'cpp'])

sample_dependencies = []
# Required for all DOCA programs
sample_dependencies += dependency('doca')
# 3rd Party dependencies
sample_dependencies += dependency('libdpdk')

sample_srcs = [
	# The sample itself
	'flow_vxlan_encap' + '_sample.c',
	# Main function for the sample's executable
	'flow_vxlan_encap' + '_main.c',
	# Common code for the DOCA library samples
	'../utils/flow_common.c',
	# Common code for all DOCA applications
	'../common/src/dpdk_utils.c',
	'../common/src/offload_rules.c',
	# Processing utils
	'../utils/processing.c',
	'../../utils/dpdk_utils2.c'
]


sample_inc_dirs  = []
# Common DOCA library logic
sample_inc_dirs += include_directories('../utils')
# Common DOCA logic (applications)
sample_inc_dirs += include_directories('../common/src')
# General utils
sample_inc_dirs += include_directories('../../utils')

executable('doca_' + 'flow_vxlan_encap', sample_srcs,
	c_args : '-Wno-missing-braces',
	dependencies : sample_dependencies,
	include_directories: sample_inc_dirs,
	install: false)

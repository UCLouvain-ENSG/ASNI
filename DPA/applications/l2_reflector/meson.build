#
# Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

flexio_build_device = '/opt/mellanox/doca/tools/build_flexio_device.sh'
device_builder = find_program(flexio_build_device)

source_file = meson.current_source_dir() + '/device/l2_reflector_device.c'

# Build device code ./build_flexio_device.sh <app name> <source file> <output dir>
dpa_code = custom_target('L2_REFLECTOR_DEVICE',
		command : [device_builder,
			APP_NAME + '_device',
			source_file,
			meson.current_build_dir()],
		output : APP_NAME + '_device.a')

dpa_device_lib = static_library(APP_NAME + '_device', link_with : dpa_code)

old_common_dir_path = common_dir_path
common_dir_path = '../../common'
subdir('host')
common_dir_path = old_common_dir_path

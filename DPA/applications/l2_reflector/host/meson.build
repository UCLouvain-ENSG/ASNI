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

app_dependencies += dependency('libibverbs')
app_dependencies += dependency('libmlx5')
app_dependencies += dependency('libbsd')

srcs = files([
	APP_NAME + '.c',
	APP_NAME + '_core.c',
	common_dir_path + '/utils.c',
])

executable(APP_NAME,
	srcs,
	c_args : base_c_args,
	include_directories: app_inc_dirs,
	dependencies: app_dependencies,
	link_with : dpa_device_lib,
	install_dir : app_install_dir,
	install: install_apps
)

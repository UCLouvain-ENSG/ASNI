

#
# Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement provided with the software product.
#

project('DPDK_PORT_FORWARD', 'C', 'CPP',
        license: 'Proprietary',
        default_options: ['buildtype=release'],
        meson_version: '>= 0.61.2'
)
# Comment this line to restore warnings of experimental DOCA features
add_project_arguments(['-ggdb'],language: ['c', 'cpp'])
inc_dirs = ['.']
dependencies = []
# Library used by the main() function
# dependencies += dependency('libbsd',static: true)
#
# dependencies += dependency('dbus-1',static: true)
#
# dependencies += dependency('systemd',static: true)
#
# dependencies += dependency('liblzma',static: true)
#
# dependencies += meson.get_compiler('c').find_library('libcrypto', dirs: '/etinfo/users2/tyunyayev/workspace/openssl/install/lib64')
#
# dependencies += meson.get_compiler('c').find_library('libssl', dirs: '/etinfo/users2/tyunyayev/workspace/openssl/install/lib64')
#
# dependencies += dependency('libdpdk',static: true)
#


dependencies += dependency('libbsd')
dependencies += dependency('libdpdk')
srcs_sender = [
        'sender.c',
        'test_utils.c',
]

srcs_sender_sg = [
        'sender_sg.c',
        'test_utils.c',
]

srcs_sender_batching = [
        'sender_sg.c',
        'test_utils.c',
]

srcs_receiver = [
        'receiver.c',
        'test_utils.c',
]

srcs_receiver_sg = [
        'receiver_sg.c',
        'test_utils.c',
]


executable('sender_cmd', srcs_sender,
        dependencies : dependencies,
        include_directories: inc_dirs,
        c_args: ['-DSG'],
        install: false)

executable('receiver_cmd', srcs_receiver,
        dependencies : dependencies,
        include_directories: inc_dirs,
        c_args: ['-DSG'],
        install: false)

# executable('sender_sg_forward_buffer', srcs_sender_sg,
#         dependencies : dependencies,
#         include_directories: inc_dirs,
#         c_args: ['-DSG','-DBUFFER'],
#         install: false)
#
# executable('sender_sg_create', srcs_sender_sg,
#         dependencies : dependencies,
#         include_directories: inc_dirs,
#         c_args: ['-DSG','-DCREATE_PACKETS'],
#         install: false)
#
# executable('sender_batching_forward', srcs_sender_sg,
#         dependencies : dependencies,
#         include_directories: inc_dirs,
#         install: false)
#
# executable('sender_batching_forward_send_loop', srcs_sender_sg,
#         dependencies : dependencies,
#         include_directories: inc_dirs,
#         c_args: ['-DSEND_LOOP'],
#         install: false)
#
# # executable('sender_batching_forward_wait_ring', srcs_sender_sg,
# #         dependencies : dependencies,
# #         include_directories: inc_dirs,
# #         c_args: ['-DWAIT_FOR_RING'],
# #         install: false)
#
# executable('sender_one_by_one_foward', srcs_sender_sg,
#         dependencies : dependencies,
#         include_directories: inc_dirs,
#         c_args: ['-DSEND_ONE_BY_ONE'],
#         install: false)
#
# executable('sender_batching_forward_no_send', srcs_sender_sg,
#         dependencies : dependencies,
#         include_directories: inc_dirs,
#         c_args: ['-DFREE_INSTEAD_OF_SEND'],
#         install: false)
#
# executable('sender_batching_create', srcs_sender_sg,
#         dependencies : dependencies,
#         include_directories: inc_dirs,
#         c_args: ['-DCREATE_PACKETS'],
#         install: false)
#
#
#

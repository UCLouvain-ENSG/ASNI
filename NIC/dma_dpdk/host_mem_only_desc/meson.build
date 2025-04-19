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

project(
  'DMA_DPDK_HOST',
  'C',
  'CPP',
  # Get version number from file.
  version: run_command(
    find_program('cat'),
    files('/opt/mellanox/doca/applications/VERSION'),
    check: true,
  ).stdout().strip(),
  license: 'Proprietary',
  default_options: ['buildtype=release'],
  meson_version: '>= 0.61.2',
)
allow_experimental_apis = true
# Comment this line to restore warnings of experimental DOCA features
add_project_arguments(
  [
    '-D DOCA_ALLOW_EXPERIMENTAL_API',
    '-DALLOW_EXPERIMENTAL_API',
    '-DALLOW_INTERNAL_API',
    # '-DFAKE_DPDK_DESC_IP_SRC',
    # '-DFAKE_DPDK_DESC_IP_DST',
    # '-DFAKE_DPDK_DESC_TIMESTAMP',
    '-DFAKE_DPDK_DESC_SIZE',
    # '-DFAKE_DPDK_DESC_PAYLOAD',
  ],
  language: ['c', 'cpp'],
)

dependencies = []
# Required for all DOCA programs
dependencies += dependency('doca')
# Library used by the main() function
dependencies += dependency('libbsd')
#
dependencies += dependency('libdpdk')

dep_net_mlx5 = declare_dependency(
  link_args: '/home/tyunyayev/dpdk-fork/install/lib/aarch64-linux-gnu/librte_net_mlx5.so.23',
)
dependencies += dep_net_mlx5

dep_common_mlx5 = declare_dependency(
  link_args: '/home/tyunyayev/dpdk-fork/install/lib/aarch64-linux-gnu/librte_common_mlx5.so.23',
)
dependencies += dep_common_mlx5

stable_srcs = [
  # The sample itself
  'stable_dma_dpdk.c',
  # Common code for the DOCA library samples
  '/opt/mellanox/doca/samples/doca_dma/dma_common.c',
  # Common code for all DOCA samples
  '../../../utils/common.c',
  # Common code for all DOCA applications
  '/opt/mellanox/doca/samples/common.c',
  '/opt/mellanox/doca/applications/common/utils.c',
  '../../../utils/set_dma_buffer.c',
  '../../../utils/port_init.c',
  '../../../utils/receive_data_from_host.c',
  '../../../utils/dma_exchange.c',
  '../../../utils/dma_jobs.c',
  '../../../utils/dpdk_utils2.c',
  '../../../utils/udp_comm.c',
  'utils/dpdk_utils.c',
]

inc_dirs = []

# Common DOCA library logic
inc_dirs += include_directories('/opt/mellanox/doca/samples/doca_dma')
# Common DOCA logic (samples)
inc_dirs += include_directories('/opt/mellanox/doca/samples')
# Common DOCA logic
inc_dirs += include_directories('/opt/mellanox/doca')
# Common DOCA logic (applications)
inc_dirs += include_directories('/opt/mellanox/doca/applications/common/')
# DMA stuff
inc_dirs += include_directories('/opt/mellanox/doca/applications/dma_copy/')
# # Including utils
inc_dirs += include_directories('../../../utils')

# Including mlx5_headers
inc_dirs += include_directories('/home/tyunyayev/dpdk-fork/drivers/common/mlx5')

# including bus utils
inc_dirs += include_directories('/home/tyunyayev/dpdk-fork/drivers/bus/pci')
# eal utils
inc_dirs += include_directories('/home/tyunyayev/dpdk-fork/lib/eal/include')

inc_dirs += include_directories('/home/tyunyayev/dpdk-fork/lib/eal/linux/include')

inc_dirs += include_directories('/home/tyunyayev/dpdk-fork/drivers/common/mlx5/linux')

inc_dirs += include_directories('/home/tyunyayev/dpdk-fork/build/drivers/common/mlx5')

executable(
  'dma_floWatcher',
  stable_srcs,
  dependencies: dependencies,
  include_directories: inc_dirs,
  c_args: [
    '-DFAKE_DPDK_MODE_DMA',
    '-DFAKE_DPDK_DESC_SIZE',
    '-DFAKE_DPDK_DESC_HASH',
    '-fms-extensions',
  ],
  install: false,
)
# executable(
#   'dma_floWatcher_cycles',
#   stable_srcs,
#   dependencies: dependencies,
#   include_directories: inc_dirs,
#   c_args: [
#     '-DHAVE_CYCLE',
#     '-DFAKE_DPDK_MODE_DMA',
#     '-DFAKE_DPDK_DESC_SIZE',
#     '-DFAKE_DPDK_DESC_HASH',
#     '-fms-extensions',
#   ],
#   install: false,
# )

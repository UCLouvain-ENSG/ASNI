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

project('DMA_DPDK_HOST', 'C', 'CPP',
        # Get version number from file.
        version: run_command(find_program('cat'),
                files('/opt/mellanox/doca/applications/VERSION'), check: true).stdout().strip(),
        license: 'Proprietary',
        default_options: ['buildtype=release'],
        meson_version: '>= 0.61.2'
)

# Comment this line to restore warnings of experimental DOCA features
add_project_arguments([
                        '-DDOCA_ALLOW_EXPERIMENTAL_API',
                        '-DALLOW_EXPERIMENTAL_API', 
                        '-DALLOW_INTERNAL_API',
                        '-DFAKE_DPDK_DESC_IP_SRC',
                        '-DFAKE_DPDK_DESC_IP_DST',
                        '-DFAKE_DPDK_DESC_TIMESTAMP',
                        '-DFAKE_DPDK_DESC_SIZE'
                        ], 
                        language: ['c', 'cpp'])

dependencies = []
# Required for all DOCA programs
dependencies += dependency('doca')
# Library used by the main() function
dependencies += dependency('libbsd')
# 
dependencies += dependency('libdpdk')
dep_net_mlx5 = declare_dependency(link_args: '/etinfo/users2/tyunyayev/workspace/dpdk-fork/install/lib/x86_64-linux-gnu/librte_net_mlx5.so.23')
dependencies += dep_net_mlx5

dep_common_mlx5 = declare_dependency(link_args: '/etinfo/users2/tyunyayev/workspace/dpdk-fork/install/lib/x86_64-linux-gnu/librte_common_mlx5.so.23')
dependencies += dep_common_mlx5
cflags = '-DALLOW_EXPERIMENTAL_API'
srcs = [
        # The sample itself
        'dma_dpdk.c',
        # Common code for the DOCA library samples
        '/opt/mellanox/doca/samples/doca_dma/dma_common.c',
        # Common code for all DOCA samples
        '/opt/mellanox/doca/samples/common.c',
        # Common code for all DOCA applications
        '/opt/mellanox/doca/applications/common/src/utils.c',
        '/opt/mellanox/doca/applications/common/src/doca_utils.c',
        # custom utils
        '../../../utils/dma_exchange.c',
        '../../../utils/receive_data_from_host.c',
        '../../../utils/dma_jobs.c',
        '../../../utils/udp_comm.c',
]

doca_srcs = [
        # The sample itself
        'doca_dma_dpdk.c',
        # Common code for the DOCA library samples
        '/opt/mellanox/doca/samples/doca_dma/dma_common.c',
        # Common code for all DOCA samples
        '/opt/mellanox/doca/samples/common.c',
        # Common code for all DOCA applications
        '/opt/mellanox/doca/applications/common/src/utils.c',
        '/opt/mellanox/doca/applications/common/src/doca_utils.c',
        # custom utils
        '../../../utils/dma_exchange.c',
        '../../../utils/receive_data_from_host.c',
        '../../../utils/dma_jobs.c',
        '../../../utils/udp_comm.c'
]

ibv_srcs = [
        # The sample itself
        'ibv_host.c',
]
stable_srcs = [
        # The main() function
        'stable_main.c',
        # The sample itself
        'stable_dma_dpdk.c',
        # Common code for the DOCA library samples
        '/opt/mellanox/doca/samples/doca_dma/dma_common.c',
        # Common code for all DOCA samples
        '/opt/mellanox/doca/samples/common.c',
        # Common code for all DOCA applications
        '/opt/mellanox/doca/applications/common/src/utils.c',
        '/opt/mellanox/doca/applications/common/src/doca_utils.c',
        # custom utils
        '../../../utils/dma_exchange.c',
        '../../../utils/receive_data_from_host.c',
        '../../../utils/dma_jobs.c',
        '../../../utils/udp_comm.c'
]

inc_dirs  = []
# Common DOCA library logic
inc_dirs += include_directories('/opt/mellanox/doca/samples/doca_dma')
# Common DOCA logic (samples)
inc_dirs += include_directories('/opt/mellanox/doca/samples')
# Common DOCA logic
inc_dirs += include_directories('/opt/mellanox/doca')
# Common DOCA logic (applications)
inc_dirs += include_directories('/opt/mellanox/doca/applications/common/src')
# Common DOCA logic (applications)
inc_dirs += include_directories('/opt/mellanox/doca/applications/common/src')
# including utils
inc_dirs += include_directories('../../../utils')
# Packet counter application
# inc_dirs += include_directories('../../applications/packet_counter')
# # including mlx5 utils
# inc_dirs += include_directories('/etinfo/users2/tyunyayev/workspace/dpdk-fork/drivers/common/mlx5')
# # including bus utils
# inc_dirs += include_directories('/etinfo/users2/tyunyayev/workspace/dpdk-fork/drivers/bus/pci')
# # eal utils
# inc_dirs += include_directories('/etinfo/users2/tyunyayev/workspace/dpdk-fork/lib/eal/include')

# inc_dirs += include_directories('/etinfo/users2/tyunyayev/workspace/dpdk-fork/lib/eal/linux/include')

# inc_dirs += include_directories('/etinfo/users2/tyunyayev/workspace/dpdk-fork/drivers/common/mlx5/linux')

# inc_dirs += include_directories('/etinfo/users2/tyunyayev/workspace/dpdk-fork/build/drivers/common/mlx5')

executable('dma-dpdk', srcs,
        dependencies : dependencies,
        include_directories: inc_dirs,
        install: false,
        c_args: cflags)


# executable('doca-dma-dpdk', doca_srcs,
#         dependencies : dependencies,
#         include_directories: inc_dirs,
#         install: false,
#         c_args: cflags)

executable('stable-dma-dpdk', stable_srcs,
        dependencies : dependencies,
        include_directories: inc_dirs,
        install: false,
        c_args: cflags)

# executable('ibv_host', ibv_srcs,
#         dependencies : dependencies,
#         include_directories: inc_dirs,
#         link_args : '-libverbs',
#         install: false,
#         c_args: cflags)

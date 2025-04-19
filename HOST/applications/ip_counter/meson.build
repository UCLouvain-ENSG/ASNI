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

project('PACKET-COUNTER', 'C', 'CPP',
        # Get version number from file.
        version: run_command(find_program('cat'),
                files('/opt/mellanox/doca/applications/VERSION'), check: true).stdout().strip(),
        license: 'Proprietary',
        default_options: ['buildtype=release'],
        meson_version: '>= 0.61.2'
)

# Comment this line to restore warnings of experimental DOCA features
add_project_arguments(['-DDOCA_ALLOW_EXPERIMENTAL_API',
                        '-DALLOW_INTERNAL_API',

                        # Define the fake DPDK mode

                        # '-DFAKE_DPDK_MODE_DMA',
                        #'-DFAKE_DPDK_MODE_DPDK_ASQ',
                        # '-DFAKE_DPDK_DESC_IP_SRC',
                        # '-DFAKE_DPDK_DESC_IP_DST',
                        # '-DFAKE_DPDK_DESC_TIMESTAMP',
                        #'-DFAKE_DPDK_DESC_SIZE',
                        # '-DFAKE_DPDK_DESC_PAYLOAD',
                        # '-DFAKE_DPDK_DESC_MAC_SRC',
                        # '-DFAKE_DPDK_DESC_MAC_DST',
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
        # The application itself
        'ip_counter.c',
        # The fake DPDK library
        '../fake_dpdk/fake_dpdk.c',
        # The underlying DMA DPDK library
        '../../dma_dpdk/host_mem_only_desc/stable_dma_dpdk.c',
        # The underlying ASQ library
        '../../dpdk/ASQ/asq.c',
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

inc_dirs  = []
inc_dirs += include_directories('./')
# Include the fake DPDK library
inc_dirs += include_directories('../fake_dpdk')
# Include the Stable DMA DPDK library
inc_dirs += include_directories('../../dma_dpdk/host_mem_only_desc')
# Include the ASQ library
inc_dirs += include_directories('../../dpdk/ASQ')
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

executable('packet_counter_asq', srcs,
        dependencies : dependencies,
        include_directories: inc_dirs,
        install: false,
        c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ','-DFAKE_DPDK_DESC_SIZE','-DFAKE_DPDK_DESC_IP_SRC'])

executable('packet_counter_asq_dpt', srcs,
        dependencies : dependencies,
        include_directories: inc_dirs,
        install: false,
        c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ_DPT','-DFAKE_DPDK_DESC_SIZE','-DFAKE_DPDK_DESC_IP_SRC'])

executable('packet_counter_dma', srcs,
        dependencies : dependencies,
        include_directories: inc_dirs,
        install: false,
        c_args: ['-DFAKE_DPDK_MODE_DMA','-DFAKE_DPDK_DESC_SIZE','-DFAKE_DPDK_DESC_IP_SRC'])



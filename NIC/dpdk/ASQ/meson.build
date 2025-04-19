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
  'DPDK_PORT_FORWARD',
  'C',
  'CPP',
  license: 'Proprietary',
  default_options: ['buildtype=release'],
  meson_version: '>= 0.61.2',
)

# Comment this line to restore warnings of experimental DOCA features
add_project_arguments(
  [
    '-DDOCA_ALLOW_EXPERIMENTAL_API',
    '-DALLOW_EXPERIMENTAL_API',
    '-DALLOW_INTERNAL_API',
    '-ggdb',
    '-g',
    '-DHAVE_CYCLE',
    # '-DFAKE_DPDK_DESC_IP_SRC',
    # '-DFAKE_DPDK_DESC_IP_DST',
    # '-DFAKE_DPDK_DESC_TIMESTAMP',
    # '-DFAKE_DPDK_DESC_SIZE',
    # '-DFAKE_DPDK_DESC_PAYLOAD',
    #'-DFAKE_DPDK_DESC_MAC_SRC',
    #'-DFAKE_DPDK_DESC_MAC_DST',
  ],
  language: ['c', 'cpp'],
)

dependencies = []
hw_dependencies = []

# Library used by the main() function
dependencies += dependency('libbsd')
hw_dependencies += dependency('libbsd')

dependencies += dependency('doca')
hw_dependencies += dependency('doca')

# Basic dependencies
dependencies += dependency('libdpdk')
hw_dependencies += dependency('libdpdk')

# Doca dependencies for the doca_flow solution

# Dependencies for HWS only
srcs = [
  # The sample itself
  'client.c',
  # To chech correct format of MAC address
  '../../../utils/MACaddress.c',
  '../../../utils/dpdk_utils2.c',
  '../../../utils/rte_flow_utils.c',
  # '../../../packet_splitting/split.c',
  # Common code for all DOCA applications
  '../../../utils/port_init.c',
  '../../../utils/receive_data_from_host.c',
  # DOCA stuff, should added back once dma is updated
  '/opt/mellanox/doca/samples/common.c',
  '/opt/mellanox/doca/applications/common/utils.c',
  # '../../../utils/common.c',
  '../../../utils/dma_setup.c',
  '../../../utils/dma_exchange.c',
  '../../../utils/dma_jobs.c',
  '../../../utils/udp_comm.c',
  '../../../utils/dpdk_utils2.c',
]

srcs_no_dma = [
  # The sample itself
  # '../../../packet_splitting/split.c',
  'client.c',
  # To chech correct format of MAC address
  '../../../utils/MACaddress.c',
  '../../../utils/dpdk_utils2.c',
  '../../../utils/rte_flow_utils.c',
  # Common code for all DOCA applications
  #
  '../../../utils/port_init.c',
  '../../../utils/receive_data_from_host.c',
  # DOCA stuff, should added back once dma is updated
  '/opt/mellanox/doca/samples/common.c',
  '/opt/mellanox/doca/samples/doca_flow/flow_common.c',
  '/opt/mellanox/doca/applications/common/utils.c',
  # '../../../utils/common.c',
  # '../../../utils/dma_setup.c',
  # '../../../utils/dma_exchange.c',
  # '../../../utils/dma_jobs.c',
  '../../../utils/udp_comm.c',
  '../../../utils/dpdk_utils2.c',
]
hw_srcs = [
  # The sample itself
  # '../../../packet_splitting/split.c',
  'hardware_solution/encapsulation/flow_vxlan_encap'
  + '_sample.c',
  # Main function for the sample's executable
  'hardware_solution/encapsulation/flow_vxlan_encap'
  + '_main.c',
  # Common code for the DOCA library samples
  # '/opt/mellanox/doca/samples/doca_flow/flow_common.c',
  '../../../utils/MACaddress.c',
  '../../../utils/dpdk_utils2.c',
  '../../../utils/common.c',
  # Common code for all DOCA applications
  # 'hardware_solution/common/src/dpdk_utils.c',
  'hardware_solution/common/src/offload_rules.c',
  'hardware_solution/common/src/flow_common.c',
  # Processing utils
  'hardware_solution/utils/processing.c',
  '../../../utils/dpdk_utils2.c',
  '/opt/mellanox/doca/samples/doca_dma/dma_common.c',
  # 'hardware_solution/common/src/dpdk_utils.c',
  'hardware_solution/common/src/dpdk_utils_asni.c',
]
baseline_src = [
  'software_baseline.c',
]
port_forwarder_src = [
  'port_forwarder.c',
]
sample_inc_dirs = []
df_inc_dirs = []
# Common DOCA library logic
sample_inc_dirs += include_directories('hardware_solution/utils')
# Common DOCA logic (applications)
sample_inc_dirs += include_directories('hardware_solution/common/src')
# General utils
# Common DOCA library logic
sample_inc_dirs += include_directories('/opt/mellanox/doca/samples/doca_dma')
# Common DOCA logic (samples)
sample_inc_dirs += include_directories('/opt/mellanox/doca/samples')
# Common DOCA logic
sample_inc_dirs += include_directories('/opt/mellanox/doca')
# Common DOCA logic (applications)
sample_inc_dirs += include_directories('/opt/mellanox/doca/applications/common/')
# # Including utils
sample_inc_dirs += include_directories('../../../utils')
sample_inc_dirs += include_directories('../../../packet_splitting')
sample_inc_dirs += include_directories('descriptor')

df_inc_dirs += sample_inc_dirs

HOME = get_option('HOME')
sample_inc_dirs += include_directories(HOME / 'dpdk-fork/drivers/common/mlx5')
sample_inc_dirs += include_directories(HOME / 'dpdk-fork/drivers/bus/pci')
sample_inc_dirs += include_directories(HOME / 'dpdk-fork/lib/eal/include')
sample_inc_dirs += include_directories(HOME / 'dpdk-fork/lib/eal/linux/include')
sample_inc_dirs += include_directories(HOME / 'dpdk-fork/drivers/common/mlx5/linux')
sample_inc_dirs += include_directories(HOME / 'dpdk-fork/build/drivers/common/mlx5')

exec_type = get_option('exec_type')
if exec_type == 'patched_dpdk'
  # executable('client_ipfill', srcs,
  #         dependencies : dependencies,
  #         include_directories: sample_inc_dirs,
  #         install: false,
  #         c_args: ['-DFAKE_DPDK_DESC_SIZE',
  #                 '-DFAKE_DPDK_MODE_DPDK_ASQ',
  #                 '-DFAKE_DPDK_DESC_ETH_TYPE',
  #                 '-DFAKE_DPDK_DESC_IP_SRC',
  #                 '-DFAKE_DPDK_DESC_IP_DST',
  #                 '-DFAKE_DPDK_DESC_PORT_SRC',
  #                 '-DFAKE_DPDK_DESC_PORT_DST',
  #                 '-DFAKE_DPDK_DESC_IP_PROTO'])
  #
  #
  # executable('client_ipfill_packet_counter', srcs,
  #         dependencies : dependencies,
  #         include_directories: sample_inc_dirs,
  #         install: false,
  #         c_args: ['-DFAKE_DPDK_DESC_SIZE','-DFAKE_DPDK_MODE_DPDK_ASQ'])
  # executable('client_asq_packet_counter', srcs,
  #          dependencies : dependencies,
  #          include_directories: sample_inc_dirs,
  #          install: false,
  #          c_args: ['-DFAKE_DPDK_DESC_SIZE','-DFAKE_DPDK_MODE_DPDK_ASQ'])

  # executable('client_minimal', srcs_no_dma,
  #         dependencies : dependencies,
  #         include_directories: sample_inc_dirs,
  #         install: false,
  #         c_args: ['-DFAKE_DPDK_DESC_SIZE',
  #                 '-DFAKE_DPDK_MODE_DPDK_ASQ',
  #         ])
  #
  #
  # executable('client_asq_cycles_hash', srcs,
  #         dependencies : dependencies,
  #         include_directories: sample_inc_dirs,
  #         install: false,
  #         c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ','-DFAKE_DPDK_DESC_SIZE','-DFAKE_DPDK_DESC_HASH','-DHAVE_CYCLE'])
  # executable('client_asq_cycles_ip', srcs,
  #         dependencies : dependencies,
  #         include_directories: sample_inc_dirs,
  #         install: false,
  #         c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ','-DFAKE_DPDK_DESC_SIZE','-DFAKE_DPDK_DESC_IP_SRC','-DHAVE_CYCLE',])
  #
  # executable(
  #   'client_l2fwd_dpt',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: sample_inc_dirs,
  #   install: false,
  #   c_args: [
  #     '-DFAKE_DPDK_MODE_DPDK_ASQ',
  #     '-DFAKE_DPDK_DESC_SIZE',
  #     '-DFAKE_DPDK_DESC_MBUF',
  #   ],
  # )
  # executable(
  #   'client_asq_dpt_floWatcher',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: sample_inc_dirs,
  #   install: false,
  #   c_args: [
  #     '-DDPT',
  #     '-DFAKE_DPDK_MODE_DPDK_ASQ',
  #     '-DFAKE_DPDK_DESC_SIZE',
  #     '-DFAKE_DPDK_DESC_HASH',
  #     '-DFAKE_DPDK_DESC_MBUF',
  #   ],
  # )
elif exec_type == 'doca_dpdk'
  # executable('client_mica', srcs_no_dma,
  #         dependencies : dependencies,
  #         include_directories: sample_inc_dirs,
  #         install: false,
  #         c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ','-DFAKE_DPDK_DESC_SIZE','-DFAKE_DPDK_DESC_OPAQUE','-DFAKE_DPDK_DESC_PAYLOAD','-ggdb','-g'])
  #
  executable(
    'client_mica_wait',
    srcs_no_dma,
    dependencies: dependencies,
    include_directories: sample_inc_dirs,
    install: false,
    c_args: [
      '-DFAKE_DPDK_MODE_DPDK_ASQ',
      '-DFAKE_DPDK_DESC_SIZE',
      '-DFAKE_DPDK_DESC_OPAQUE',
      '-DFAKE_DPDK_DESC_PAYLOAD',
      '-DWAIT_FOR_PACKETS',
    ],
  )

  executable(
    'client_vignat_prefetch',
    srcs_no_dma,
    dependencies: dependencies,
    include_directories: sample_inc_dirs,
    install: false,
    c_args: [
      '-DFAKE_DPDK_DESC_SIZE',
      '-DFAKE_DPDK_MODE_DPDK_ASQ',
      '-DFAKE_DPDK_DESC_ETH_TYPE',
      '-DFAKE_DPDK_DESC_IP_SRC',
      '-DFAKE_DPDK_DESC_IP_DST',
      '-DFAKE_DPDK_DESC_PORT_SRC',
      '-DFAKE_DPDK_DESC_PORT_DST',
      '-DFAKE_DPDK_DESC_IP_PROTO',
    ],
  )
  executable(
    'client_vignat_no_prefetch',
    srcs_no_dma,
    dependencies: dependencies,
    include_directories: sample_inc_dirs,
    install: false,
    c_args: [
      '-DFAKE_DPDK_DESC_SIZE',
      '-DFAKE_DPDK_MODE_DPDK_ASQ',
    ],
  )

    rtmodes = {
      'normal':['-DDUMMY'],
        'pad0' : ['-DDUMMY2'],
       'pad4' : ['-DFAKE_DPDK_DESC_PAD=4'],
       'pad8' : ['-DFAKE_DPDK_DESC_PAD=8'],
       'pad16' : ['-DFAKE_DPDK_DESC_PAD=16'],
       'pad32' : ['-DFAKE_DPDK_DESC_PAD=32'],
       'pad64' : ['-DFAKE_DPDK_DESC_PAD=64'],
       'pad128' : ['-DFAKE_DPDK_DESC_PAD=128']
    }
    foreach  rtkey, rtsuffix : rtmodes
      executable(
        'client_asq_floWatcher_'+rtkey,
        srcs_no_dma,
        dependencies: dependencies,
        include_directories: sample_inc_dirs,
        install: false,
        c_args: [
          '-DFAKE_DPDK_MODE_DPDK_ASQ',
          '-DFAKE_DPDK_DESC_SIZE',
          '-DFAKE_DPDK_DESC_HASH'
        ]+rtsuffix,
      )
    endforeach
  executable(
    'client_asq_floWatcher',
    srcs_no_dma,
    dependencies: dependencies,
    include_directories: sample_inc_dirs,
    install: false,
    c_args: [
      '-DFAKE_DPDK_MODE_DPDK_ASQ',
      '-DFAKE_DPDK_DESC_SIZE',
      '-DFAKE_DPDK_DESC_HASH',
    ],
  )
  executable(
    'client_asq_floWatcher_ip',
    srcs_no_dma,
    dependencies: dependencies,
    include_directories: sample_inc_dirs,
    install: false,
    c_args: [
      '-DFAKE_DPDK_MODE_DPDK_ASQ',
      '-DFAKE_DPDK_DESC_SIZE',
      '-DFAKE_DPDK_DESC_HASH',
      '-DFAKE_DPDK_DESC_IP_SRC',
    ],
  )
  
  executable(
    'client_asq_floWatcher_dp',
    srcs_no_dma,
    dependencies: dependencies,
    include_directories: sample_inc_dirs,
    install: false,
    c_args: [
      '-DFAKE_DPDK_MODE_DPDK_ASQ',
      '-DFAKE_DPDK_DESC_SIZE',
      '-DFAKE_DPDK_DESC_HASH',
      '-DFAKE_DPDK_DESC_DP',
      '-DDP',
    ],
  )
  executable(
    'client_asq_floWatcher_pp',
    srcs_no_dma,
    dependencies: dependencies,
    include_directories: sample_inc_dirs,
    install: false,
    c_args: [
      '-DFAKE_DPDK_MODE_DPDK_ASQ',
      '-DFAKE_DPDK_DESC_SIZE',
      '-DFAKE_DPDK_DESC_HASH',
      '-DPP',
    ],
  )
  executable(
    'client_asq_floWatcher_pp_exp_desc',
    srcs_no_dma,
    dependencies: dependencies,
    include_directories: sample_inc_dirs,
    install: false,
    c_args: [
      '-DFAKE_DPDK_MODE_DPDK_ASQ',
      '-DFAKE_DPDK_DESC_SIZE',
      '-DFAKE_DPDK_DESC_HASH',
      '-DFAKE_DPDK_DESC_PAYLOAD',
      '-DPP',
    ],
  )
  executable(
    'client_asq_floWatcher_wait',
    srcs_no_dma,
    dependencies: dependencies,
    include_directories: sample_inc_dirs,
    install: false,
    c_args: [
      '-DFAKE_DPDK_MODE_DPDK_ASQ',
      '-DFAKE_DPDK_DESC_SIZE',
      '-DFAKE_DPDK_DESC_HASH',
      '-DWAIT_FOR_PACKETS',
    ],
  )
  #
  # executable('client_l2fwd_hash', srcs_no_dma,
  #         dependencies : dependencies,
  #         include_directories: sample_inc_dirs,
  #         install: false,
  #         c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ','-DFAKE_DPDK_DESC_SIZE','-DFAKE_DPDK_DESC_HASH'])
  executable(
    'client_l2fwd',
    srcs_no_dma,
    dependencies: dependencies,
    include_directories: sample_inc_dirs,
    install: false,
    c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ', '-DFAKE_DPDK_DESC_SIZE'],
  )
  executable(
    'client_l2fwd_wait',
    srcs_no_dma,
    dependencies: dependencies,
    include_directories: sample_inc_dirs,
    install: false,
    c_args: [
      '-DFAKE_DPDK_MODE_DPDK_ASQ',
      '-DFAKE_DPDK_DESC_SIZE',
      '-DWAIT_FOR_PACKETS',
    ],
  )
  # executable(
  #   'client_hw_floWatcher',
  #   hw_srcs,
  #   c_args: '-Wno-missing-braces -Wno-deprecated-declarations -g',
  #   dependencies: hw_dependencies,
  #   include_directories: df_inc_dirs,
  #   install: false,
  #   c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ_HW_DD'],
  # )
  # executable(
  #   'client_hw_floWatcher_cycles',
  #   hw_srcs,
  #   c_args: '-Wno-missing-braces -Wno-deprecated-declarations -g',
  #   dependencies: hw_dependencies,
  #   include_directories: df_inc_dirs,
  #   install: false,
  #   c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ_HW_DD', '-DHAVE_CYCLE'],
  # )
  executable(
    'client_hw_floWatcher_soft_reordering',
    hw_srcs,
    c_args: '-Wno-missing-braces -Wno-deprecated-declarations -g',
    dependencies: hw_dependencies,
    include_directories: df_inc_dirs,
    install: false,
    c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ_HW_DD', '-DSOFT_REORDERING'],
  )

  executable(
    'client_hw_floWatcher',
    hw_srcs,
    c_args: '-Wno-missing-braces -Wno-deprecated-declarations -g',
    dependencies: hw_dependencies,
    include_directories: df_inc_dirs,
    install: false,
    c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ_HW_DD', '-DHAVE_CYCLE'],
  )
  # executable('port_forwarder', port_forwarder_src,
  #         dependencies : dependencies,
  #         install: false)
  # executable('client_xchg', srcs,
  #         dependencies : dependencies,
  #         include_directories: sample_inc_dirs,
  #         install: false,
  #         c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ','-DFAKE_DPDK_DESC_SIZE'])
  # executable('client_xchg_testing', srcs,
  #         dependencies : dependencies,
  #         include_directories: sample_inc_dirs,
  #         install: false,
  #         c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ','-DFAKE_DPDK_DESC_SIZE','-DTESTING'])

else
  message('Unknown exec_type')
endif

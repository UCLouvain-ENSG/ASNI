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
  'FloWatcher',
  'C',
  'CPP',
  license: 'Proprietary',
  default_options: ['buildtype=release', 'warning_level=1', 'b_lto=true'],
  meson_version: '>= 0.61.2',
)

# Comment this line to restore warnings of experimental DOCA features
add_project_arguments(
  [
    '-DDOCA_ALLOW_EXPERIMENTAL_API',
    '-DALLOW_INTERNAL_API',

    # Define the fake DPDK mode

    # '-DFAKE_DPDK_MODE_DMA', '-DFAKE_DPDK_MODE_DPDK_ASQ',
    # '-DFAKE_DPDK_MODE_DPDK_ASQ_HW_DP', '-DFAKE_DPDK_MODE_DPDK_ASQ_HW_DD',

    # Select the fake DPDK fields to use

    # '-DFAKE_DPDK_DESC_IP_SRC', '-DFAKE_DPDK_DESC_IP_DST',
    # '-DFAKE_DPDK_DESC_TIMESTAMP',
    #'-DFAKE_DPDK_DESC_SIZE', '-DFAKE_DPDK_DESC_PAYLOAD',
    #'-DFAKE_DPDK_DESC_MAC_SRC', '-DFAKE_DPDK_DESC_MAC_DST',,
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
# dep_net_mlx5 = declare_dependency(link_args:
# '/etinfo/users2/tyunyayev/workspace/dpdk-fork/install/lib/x86_64-linux-gnu/librte_net_mlx5.so.23')
# dependencies += dep_net_mlx5
#
# dep_common_mlx5 = declare_dependency(link_args:
# '/etinfo/users2/tyunyayev/workspace/dpdk-fork/install/lib/x86_64-linux-gnu/librte_common_mlx5.so.23')
# dependencies += dep_common_mlx5
cflags = '-DALLOW_EXPERIMENTAL_API'
srcs = [
  # The application itself
  'floWatcher.c',
  # The fake DPDK library
  '../../fake_dpdk/fake_dpdk.c',
  # The underlying DMA DPDK library
  # '../../../dma_dpdk/host_mem_only_desc/stable_dma_dpdk.c',
  # The underlying ASQ library
  '../../../dpdk/ASQ/asq.c',
  # The underlying BASELINE library
  '../../../dpdk/BASELINE/baseline.c',
  # Common code for the DOCA library samples
  # '/opt/mellanox/doca/samples/doca_dma/dma_common.c',
  # Common code for all DOCA samples
  '/opt/mellanox/doca/samples/common.c',
  # Common code for all DOCA applications
  '/opt/mellanox/doca/applications/common/utils.c',
  # '/opt/mellanox/doca/applications/common/src/doca_utils.c',
  # custom utils
  # '../../../../utils/dma_exchange.c',
  '../../../../utils/receive_data_from_host.c',
  # '../../../../utils/dma_jobs.c',
  '../../../../utils/udp_comm.c',
  '../../../../utils/dgu_utils.c',
  # '../../../../utils/common.c',
]

inc_dirs = []
inc_dirs += include_directories('./')
inc_dirs += include_directories('../../')

# Include the fake DPDK library
inc_dirs += include_directories('../../fake_dpdk')
# Include the Stable DMA DPDK library
inc_dirs += include_directories('../../../dma_dpdk/host_mem_only_desc')
# Include the ASQ library
inc_dirs += include_directories('../../../dpdk/ASQ')

inc_dirs += include_directories('../../../dpdk/BASELINE')
# Common DOCA library logic
inc_dirs += include_directories('/opt/mellanox/doca/samples/doca_dma')
# Common DOCA logic
inc_dirs += include_directories('/opt/mellanox/doca')
# Common DOCA logic (samples)
inc_dirs += include_directories('/opt/mellanox/doca/samples')
# DOCA stuff
inc_dirs += include_directories('/opt/mellanox/doca/include')
# including utils
inc_dirs += include_directories('../../../../utils')

# For loop to create all the debug exeutales

DPDK_VER = get_option('DPDK_VER')
if DPDK_VER == 'XCHG'
  inc_dirs += include_directories('../../../xchg_ver')
  inc_dirs += include_directories('../../../dpdk/ASQ')
  srcs_xchg = [
    'floWatcher.c',
    '../../../xchg_ver/xchg_ver23.c',
    '../../../xchg_ver/xchg23.c',
    '../../fake_dpdk/fake_dpdk.c',
    '../../../dpdk/ASQ/asq.c',
    '../../../../utils/dgu_utils.c',

  ]
  pkgconfig = find_program('pkg-config')
  cflags_cmd = run_command(pkgconfig, '--cflags', 'libdpdk', check: true)
  ldflags_cmd = run_command(pkgconfig, '--static', '--libs', 'libdpdk', check: true)
  cflags = cflags_cmd.stdout().split()
  ldflags = ldflags_cmd.stdout().split()

  xchg_dependencies = []
  # Library used by the main() function
  xchg_dependencies += dependency('libbsd')

  suffixes = {
    'ip': '-DIP_WORKLOAD',
    'heavy': '-DCRC_HEAVY_WORKLOAD',
    'light': '-DCRC_LIGHT_WORKLOAD',
    'base': '-DDUMMY',
  }

  foreach key, suffix : suffixes
    rtmodes = {
      'normal':['-DDUMMY'],
      'nopd':'-DNO_PREFETCH_DESC',
   #   'nopp':'-DNO_PREFETCH_PAYLOAD',
    #  'nopdpp':['-DNO_PREFETCH_DESC', '-DNO_PREFETCH_PAYLOAD'],
       'rtc':['-DHAVE_RTC'],
       'rtcnopp':['-DHAVE_RTC', '-DNO_PREFETCH_PAYLOAD'],
       'pad0':['-DDUMMY2'],
       'pad4' : ['-DFAKE_DPDK_DESC_PAD=4'],
       'pad8' : ['-DFAKE_DPDK_DESC_PAD=8'],
       'pad16' : ['-DFAKE_DPDK_DESC_PAD=16'],
       'pad32' : ['-DFAKE_DPDK_DESC_PAD=32'],
       'pad64' : ['-DFAKE_DPDK_DESC_PAD=64'],
       'pad128' : ['-DFAKE_DPDK_DESC_PAD=128']
    }
    foreach  rtkey, rtsuffix : rtmodes
      name = 'xchg_asni_floWatcher_' + key + '_cycles_' + rtkey
      executable(
        name,
        srcs_xchg,
        dependencies: xchg_dependencies,
        include_directories: inc_dirs,
        install: false,
        link_args: ldflags
        + [
          '-flto',
        ],
        c_args: cflags
        + [
          '-DFAKE_DPDK_DESC_HASH',
          '-DFAKE_DPDK_MODE_XCHG_ASNI', suffix,
          '-DFAKE_DPDK_DESC_SIZE',
          '-fms-extensions',
          '-fcommon',
          '-DHAVE_CYCLE',
          '-flto',
        ] + rtsuffix,
      )
    endforeach


      name = 'xchg_asni_floWatcher_' + key + '_cycles'
      executable(
        name,
        srcs_xchg,
        dependencies: xchg_dependencies,
        include_directories: inc_dirs,
        install: false,
        link_args: ldflags
        + [
          '-flto',
        ],
        c_args: cflags
        + [
          '-DFAKE_DPDK_DESC_HASH',
          '-DFAKE_DPDK_MODE_XCHG_ASNI', suffix,
          '-DFAKE_DPDK_DESC_SIZE',
          '-fms-extensions',
          '-fcommon',
          '-DHAVE_CYCLE',
          '-flto',
        ],
      )
  endforeach
  foreach key, suffix : suffixes
    name = 'xchg_floWatcher_' + key + '_cycles'
    executable(
      name,
      srcs_xchg,
      dependencies: xchg_dependencies,
      include_directories: inc_dirs,
      install: false,
      link_args: ldflags
      + [
        '-flto',
      ],
      c_args: cflags
      + [
        '-DFAKE_DPDK_DESC_HASH',
        '-DFAKE_DPDK_MODE_XCHG', suffix,
        '-fms-extensions',
        '-fcommon',
        '-DHAVE_CYCLE',
        '-flto',
      ],
    )


  endforeach

elif DPDK_VER == 'DPDK'
  prefixes = ['baseline', 'mprq', 'asq_dd', 'asq_dp', 'asq_pp', 'asq_pp_exp_desc']
  app_name = 'floWatcher'
  suffixes = {
    'ip': '-DIP_WORKLOAD',
    'heavy': '-DCRC_HEAVY_WORKLOAD',
    'light': '-DCRC_LIGHT_WORKLOAD',
    'base': '-DDUMMY',
  }

  baseline_flags = [
    '-DFAKE_DPDK_MODE_DPDK_BASELINE',
    '-DHAVE_CYCLE',
    '-fms-extensions',
    '-fcommon',
  ]
  mprq_flags = [
    '-DFAKE_DPDK_MODE_DPDK_BASELINE',
    '-DHAVE_CYCLE',
    '-DHAVE_MPRQ',
    '-fms-extensions',
    '-fcommon',
  ]
  asq_dd_flags = [
    '-DFAKE_DPDK_MODE_DPDK_ASQ',
    '-DFAKE_DPDK_DESC_SIZE',
    '-DFAKE_DPDK_DESC_HASH',
    '-DHAVE_CYCLE',
    '-fcommon',
  ]
  asq_dp_flags = [
    '-DFAKE_DPDK_MODE_DPDK_ASQ',
    '-DFAKE_DPDK_DESC_SIZE',
    '-DFAKE_DPDK_DESC_HASH',
    '-DFAKE_DPDK_MODE_DPDK_ASQ_DP',
    '-DHAVE_CYCLE',
    '-fcommon',
  ]

  asq_pp_flags = [
    '-DFAKE_DPDK_MODE_DPDK_ASQ',
    '-DFAKE_DPDK_DESC_SIZE',
    '-DFAKE_DPDK_DESC_HASH',
    '-DFAKE_DPDK_MODE_DPDK_ASQ_PP',
    '-DHAVE_CYCLE',
    '-fcommon',
  ]
  asq_pp_exp_desc_flags = [
    '-DFAKE_DPDK_MODE_DPDK_ASQ',
    '-DFAKE_DPDK_DESC_SIZE',
    '-DFAKE_DPDK_DESC_HASH',
    '-DFAKE_DPDK_MODE_DPDK_ASQ_PP_EXP_DESC',
    '-DFAKE_DPDK_DESC_PAYLOAD',
    '-DHAVE_CYCLE',
    '-fcommon',
  ]
  dic_of_flags = {
    'baseline': baseline_flags,
    'mprq': mprq_flags,
    'asq_dd': asq_dd_flags,
    'asq_dp': asq_dp_flags,
    'asq_pp': asq_pp_flags,
    'asq_pp_exp_desc': asq_pp_exp_desc_flags,
  }
  foreach prefix : prefixes
    foreach key0, suffix0 : suffixes
      name_simple = prefix + '_' + app_name + '_' + key0 + '_cycles'
      executable(
        name_simple,
        srcs,
        dependencies: dependencies,
        include_directories: inc_dirs,
        install: false,
        c_args: dic_of_flags[prefix]
        + [
          suffix0,
        ],
      )
    endforeach
  endforeach
  rtmodes = {
       'pad0':['-DDUMMY'],
       'pad4' : ['-DFAKE_DPDK_DESC_PAD=4'],
       'pad8' : ['-DFAKE_DPDK_DESC_PAD=8'],
       'pad16' : ['-DFAKE_DPDK_DESC_PAD=16'],
       'pad32' : ['-DFAKE_DPDK_DESC_PAD=32'],
       'pad64' : ['-DFAKE_DPDK_DESC_PAD=64'],
       'pad128' : ['-DFAKE_DPDK_DESC_PAD=128']
  }
  foreach  rtkey, rtsuffix : rtmodes
    name = 'baseline_floWatcher_base_cycles_' + rtkey
    executable(
      name,
      srcs,
      dependencies: dependencies,
      include_directories: inc_dirs,
      install: false,
      c_args: baseline_flags + rtsuffix,
    )
    endforeach

  # executable(
  #   'baseline_floWatcher',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: ['-DFAKE_DPDK_MODE_DPDK_BASELINE', '-fms-extensions', '-fcommon'],
  # )
  #
  # executable(
  #   'baseline_floWatcher_cycles',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: [
  #     '-DFAKE_DPDK_MODE_DPDK_BASELINE',
  #     '-fms-extensions',
  #     '-fcommon',
  #     '-DHAVE_CYCLE',
  #   ],
  # )
  #
  # executable(
  #   'baseline_floWatcher_ip_cycles',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: [
  #     '-DFAKE_DPDK_MODE_DPDK_BASELINE',
  #     '-fms-extensions',
  #     '-fcommon',
  #     '-DIP_WORKLOAD',
  #     '-DHAVE_CYCLE',
  #   ],
  # )

  executable(
    'hw_dp_floWatcher_base_cycles',
    srcs,
    dependencies: dependencies,
    include_directories: inc_dirs,
    install: false,
    c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ_HW_DP', '-fcommon', '-DHAVE_CYCLE'],
  )
  executable(
    'asq_dd_ip_floWatcher_base_cycles',
    srcs,
    dependencies: dependencies,
    include_directories: inc_dirs,
    install: false,
    c_args: [
      '-DFAKE_DPDK_DESC_IP_SRC',
      '-DFAKE_DPDK_DESC_SIZE',
      '-DFAKE_DPDK_MODE_DPDK_ASQ',
      '-DFAKE_DPDK_DESC_HASH',
      '-fcommon',
      '-DHAVE_CYCLE',
    ],
  )
  executable(
    'hw_dd_floWatcher_base_cycles',
    srcs,
    dependencies: dependencies,
    include_directories: inc_dirs,
    install: false,
    c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ_HW_DD', '-fcommon', '-DHAVE_CYCLE'],
  )
  #
  # executable(
  #   'hw_dd_floWatcher_debug',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: [
  #     '-DFAKE_DPDK_MODE_DPDK_ASQ_HW_DD',
  #     '-fcommon',
  #     '-DHAVE_CYCLE',
  #     '-DASNI_DEBUG',
  #   ],
  # )
  # executable(
  #   'dma_floWatcher_cycles',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: [
  #     '-DFAKE_DPDK_MODE_DMA',
  #     '-DFAKE_DPDK_DESC_SIZE',
  #     '-DFAKE_DPDK_DESC_HASH',
  #     '-fcommon',
  #     '-DHAVE_CYCLE',
  #   ],
  # )
  #
  # executable(
  #   'asq_dpt_floWatcher_cycles',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: [
  #     '-DFAKE_DPDK_MODE_DPDK_ASQ_DPT',
  #     '-DFAKE_DPDK_DESC_SIZE',
  #     '-DDFAKE_DPDK_DESC_PAYLOAD',
  #     '-DFAKE_DPDK_DESC_HASH',
  #     '-fcommon',
  #     '-DHAVE_CYCLE',
  #   ],
  # )

  # executable(
  #   'hw_dp_floWatcher',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ_HW_DP', '-fcommon'],
  # )
  # executable(
  #   'hw_dd_floWatcher',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: ['-DFAKE_DPDK_MODE_DPDK_ASQ_HW_DD', '-fcommon'],
  # )

  # executable(
  #   'asq_floWatcher',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: [
  #     '-DFAKE_DPDK_MODE_DPDK_ASQ',
  #     '-DFAKE_DPDK_DESC_SIZE',
  #     '-DFAKE_DPDK_DESC_HASH',
  #     '-fcommon',
  #   ],
  # )
  #
  # executable(
  #   'asq_floWatcher_cycles',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: [
  #     '-DFAKE_DPDK_MODE_DPDK_ASQ',
  #     '-DFAKE_DPDK_DESC_SIZE',
  #     '-DFAKE_DPDK_DESC_HASH',
  #     '-fcommon',
  #     '-DHAVE_CYCLE',
  #   ],
  # )
  #
  # executable(
  #   'asq_floWatcher_debug',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: [
  #     '-DFAKE_DPDK_MODE_DPDK_ASQ',
  #     '-DFAKE_DPDK_DESC_SIZE',
  #     '-DFAKE_DPDK_DESC_HASH',
  #     '-fcommon',
  #     '-DHAVE_CYCLE',
  #     '-DASNI_DEBUG',
  #   ],
  # )
  #
  # executable(
  #   'asq_floWatcher_ip_cycles',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: [
  #     '-DFAKE_DPDK_MODE_DPDK_ASQ',
  #     '-DFAKE_DPDK_DESC_SIZE',
  #     '-DFAKE_DPDK_DESC_HASH',
  #     '-DIP_WORKLOAD',
  #     '-DHAVE_CYCLE',
  #     '-fcommon',
  #   ],
  # )
  # executable(
  #   'asq_dp_floWatcher_cycles',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: [
  #     '-DFAKE_DPDK_MODE_DPDK_ASQ',
  #     '-DFAKE_DPDK_DESC_SIZE',
  #     '-DFAKE_DPDK_DESC_HASH',
  #     '-DFAKE_DPDK_MODE_DPDK_ASQ_DP',
  #     '-DDP',
  #     '-DHAVE_CYCLE',
  #     '-fcommon',
  #   ],
  # )
  #
  # executable(
  #   'asq_dp_floWatcher_ip_cycles',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: [
  #     '-DFAKE_DPDK_MODE_DPDK_ASQ',
  #     '-DFAKE_DPDK_DESC_SIZE',
  #     '-DFAKE_DPDK_DESC_HASH',
  #     '-DFAKE_DPDK_MODE_DPDK_ASQ_DP',
  #     '-DDP',
  #     '-DHAVE_CYCLE',
  #     '-DIP_WORKLOAD',
  #     '-fcommon',
  #
  #   ],
  # )
  # executable(
  #   'asq_dp_floWatcher',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: [
  #     '-DFAKE_DPDK_MODE_DPDK_ASQ',
  #     '-DFAKE_DPDK_DESC_SIZE',
  #     '-DFAKE_DPDK_DESC_HASH',
  #     '-DFAKE_DPDK_MODE_DPDK_ASQ_DP',
  #     '-DDP',
  #     '-fcommon',
  #   ],
  # )

  # executable(
  #   'dma_floWatcher',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: [
  #     '-DFAKE_DPDK_MODE_DMA',
  #     '-DFAKE_DPDK_DESC_SIZE',
  #     '-DFAKE_DPDK_DESC_HASH',
  #     '-fcommon',
  #   ],
  # )
  #
  # executable(
  #   'asq_dpt_floWatcher',
  #   srcs,
  #   dependencies: dependencies,
  #   include_directories: inc_dirs,
  #   install: false,
  #   c_args: [
  #     '-DFAKE_DPDK_MODE_DPDK_ASQ_DPT',
  #     '-DFAKE_DPDK_DESC_SIZE',
  #     '-DDFAKE_DPDK_DESC_PAYLOAD',
  #     '-DFAKE_DPDK_DESC_HASH',
  #     '-fcommon',
  #   ],
  # )
else
  message('Unknown DPDK_VER')
endif

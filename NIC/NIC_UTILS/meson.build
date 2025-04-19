
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
add_project_arguments(['-DDOCA_ALLOW_EXPERIMENTAL_API',
                        '-DALLOW_EXPERIMENTAL_API', 
                        '-DALLOW_INTERNAL_API',
                        # '-DFAKE_DPDK_DESC_IP_SRC',
                        # '-DFAKE_DPDK_DESC_IP_DST',
                        # '-DFAKE_DPDK_DESC_TIMESTAMP',
                        '-DFAKE_DPDK_DESC_SIZE',
                        # '-DFAKE_DPDK_DESC_PAYLOAD',
                        #'-DFAKE_DPDK_DESC_MAC_SRC',
                        #'-DFAKE_DPDK_DESC_MAC_DST',
                        ],
                        language: ['c', 'cpp'])


dependencies = []
hw_dependencies = []

# Library used by the main() function
dependencies += dependency('libbsd')
hw_dependencies += dependency('libbsd')

dependencies += dependency('doca')
hw_dependencies += dependency('doca')
# Basic dependencies
#dependencies += dependency('libdpdk-fork')
dependencies += dependency('libdpdk')
hw_dependencies += dependency('libdpdk')

# Doca dependencies for the doca_flow solution

# Dependencies for HWS only
port_forwarder_src = [
  'port_forwarder.c',
  ]

software_forwarder = [
  'software_forwarder.c',
  ]
df_inc_dirs = []


port_forwarder_busy = [
  'port_forwarder_busy.c',
  ]
forwarder_with_latency = [
  'forwarder_with_latency.c',
  ]
executable('port_forwarder', port_forwarder_src,
        dependencies : dependencies,
        install: false)
executable('software_forwarder', software_forwarder,
        dependencies : dependencies,
        install: false)
executable('software_forwarder_cycles', software_forwarder,
        dependencies : dependencies,
        c_args: ['-DHAVE_CYCLE'],
        install: false)
executable('port_forwarder_busy', port_forwarder_busy,
        dependencies : dependencies,
        install: false)
executable('forwarder_with_latency', forwarder_with_latency,
        dependencies : dependencies,
        install: false)

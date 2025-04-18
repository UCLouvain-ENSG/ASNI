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

project('MULTI_APP_HELPER', 'C', 'CPP',
        license: 'Proprietary',
        default_options: ['buildtype=release'],
        meson_version: '>= 0.61.2'
)

# Comment this line to restore warnings of experimental DOCA features
add_project_arguments(['-DDOCA_ALLOW_EXPERIMENTAL_API',
                        '-DALLOW_EXPERIMENTAL_API', 
                        '-DALLOW_INTERNAL_API',
                        '-ggdb',
                        '-g',
                        ],
                        language: ['c', 'cpp'])

dependencies = dependency('libdpdk')
directories = include_directories('../../../../utils')
srcs = [
        'rule_offloader.c',
        '../../../../utils/rte_flow_utils.c',
]

executable('multi_app_helper', srcs,
        dependencies : dependencies,
        include_directories: directories,
        install: false)


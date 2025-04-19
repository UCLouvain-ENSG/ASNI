cmake_minimum_required(VERSION 2.8.11)
cmake_policy(SET CMP0003 NEW)
project(vignat C CXX)
find_package (Threads REQUIRED)
option(ENABLE_ASAN "Enable AddressSanitizer (ASAN) for debugging" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer (UBSan) for debugging" OFF)

set(CMAKE_C_STANDARD 11)

# Add compilation flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DENABLE_LOG")
set(XCHG_LIBRARIES rte_flow_classify rte_pipeline  rte_table  rte_port  rte_pdump rte_distributor rte_ip_frag rte_meter rte_fib rte_rib rte_lpm rte_acl rte_jobstats rte_metrics rte_bitratestats rte_latencystats rte_efd rte_bpf rte_ipsec rte_cfgfile rte_gro rte_gso rte_hash rte_member rte_mbuf rte_net rte_ethdev rte_bbdev rte_cryptodev rte_security rte_compressdev rte_eventdev rte_rawdev rte_timer rte_mempool rte_stack rte_mempool_ring rte_ring rte_pci rte_cmdline rte_reorder rte_sched rte_rcu rte_bus_pci rte_bus_vdev rte_mempool_bucket rte_mempool_stack rte_common_mlx5 rte_pmd_mlx5 ibverbs mlx5 rte_bus_ifpga numa rt m dl rte_eal rte_kvargs)


message(STATUS "Initial CMAKE_C_FLAGS=${CMAKE_C_FLAGS}")

# Set GCC as compiler
# set(CMAKE_C_COMPILER "gcc")
set(CMAKE_C_FLAGS "-O3 -std=gnu99 -ggdb -g -Wextra -Wall -Wno-deprecated-declarations ${CMAKE_C_FLAGS}")

if(DISABLE_DEBUG_PRINTF)
    set(CMAKE_C_FLAGS "-DDISABLE_DEBUG_PRINTF ${CMAKE_C_FLAGS}")
endif()

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CMakePushCheckState)

# Print cwd
message(STATUS "CMAKE_CURRENT_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}")
# Add include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../utils/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../HOST/applications/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../dpdk/ASQ)
# add_definitions(-isystem $ENV{RTE_SDK}/$ENV{RTE_TARGET}/include -include rte_config.h)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBDPDK REQUIRED IMPORTED_TARGET libdpdk)

# Setup DPDK version
add_executable(vignat_asni_offload_tx_prefetch
    src/main.c
    src/state.c
    src/nat_config.c
    src/nat_flowmanager.c
    src/nat_main.c
    src/nf-util.c
    src/nf.c
    src/utils/cht.c
    src/utils/double-chain.c
    src/utils/double-chain-impl.c
    src/utils/double-map.c
    src/utils/ether.c
    src/utils/expirator.c
    src/utils/lpm-dir-24-8.c
    src/utils/map.c
    src/utils/map-impl.c
    src/utils/map-impl-pow2.c
    src/utils/packet-io.c
    src/utils/vector.c
    src/utils/vigor-time.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../fake_dpdk/fake_io.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../utils/dgu_utils.c
)

set_target_properties(vignat_asni_offload_tx_prefetch PROPERTIES COMPILE_FLAGS "-DFAKE_DPDK_MODE_DPDK_ASQ_OFFLOAD_TX -DFAKE_DPDK_IO_ASQ_OFFLOAD_TX -DFAKE_DPDK_DESC_IP_SRC -DFAKE_DPDK_DESC_IP_DST -DFAKE_DPDK_DESC_PORT_DST -DFAKE_DPDK_DESC_PORT_SRC -DFAKE_DPDK_DESC_IP_PROTO -DFAKE_DPDK_DESC_ETH_TYPE -DFAKE_DPDK_DESC_SIZE")

add_executable(vignat_asni_offload_tx_no_prefetch
    src/main.c
    src/state.c
    src/nat_config.c
    src/nat_flowmanager.c
    src/nat_main.c
    src/nf-util.c
    src/nf.c
    src/utils/cht.c
    src/utils/double-chain.c
    src/utils/double-chain-impl.c
    src/utils/double-map.c
    src/utils/ether.c
    src/utils/expirator.c
    src/utils/lpm-dir-24-8.c
    src/utils/map.c
    src/utils/map-impl.c
    src/utils/map-impl-pow2.c
    src/utils/packet-io.c
    src/utils/vector.c
    src/utils/vigor-time.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../fake_dpdk/fake_io.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../utils/dgu_utils.c
)

set_target_properties(vignat_asni_offload_tx_no_prefetch PROPERTIES COMPILE_FLAGS "-DFAKE_DPDK_MODE_DPDK_ASQ_OFFLOAD_TX -DFAKE_DPDK_IO_ASQ_OFFLOAD_TX -DFAKE_DPDK_DESC_SIZE")

# Set WITH_DPDK flag
# set_target_properties(vignat_asni_offload_tx PROPERTIES COMPILE_DEFINITIONS "-DFAKE_DPDK_IO_DPDK")
# Include DPDK headers
target_include_directories(vignat_asni_offload_tx_no_prefetch PRIVATE ${LIBDPDK_INCLUDE_DIRS})
# Link with DPDK
target_link_libraries(vignat_asni_offload_tx_no_prefetch PkgConfig::LIBDPDK)
# Include DPDK headers
target_include_directories(vignat_asni_offload_tx_prefetch PRIVATE ${LIBDPDK_INCLUDE_DIRS})
# Link with DPDK
target_link_libraries(vignat_asni_offload_tx_prefetch PkgConfig::LIBDPDK)

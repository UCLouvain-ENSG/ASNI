cmake_minimum_required(VERSION 2.8.11)
cmake_policy(SET CMP0003 NEW)
project(vignat C CXX)
find_package (Threads REQUIRED)
option(ENABLE_ASAN "Enable AddressSanitizer (ASAN) for debugging" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer (UBSan) for debugging" OFF)

set(CMAKE_C_STANDARD 11)

# Add compilation flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DENABLE_LOG -DFAKE_DPDK_MODE_DPDK_ASQ -DFAKE_DPDK_DESC_IP_SRC -DFAKE_DPDK_DESC_IP_DST -DFAKE_DPDK_DESC_PORT_DST -DFAKE_DPDK_DESC_PORT_SRC -DFAKE_DPDK_DESC_IP_PROTO -DFAKE_DPDK_DESC_ETH_TYPE")
set(XCHG_LIBRARIES rte_flow_classify rte_pipeline  rte_table  rte_port  rte_pdump rte_distributor rte_ip_frag rte_meter rte_fib rte_rib rte_lpm rte_acl rte_jobstats rte_metrics rte_bitratestats rte_latencystats rte_efd rte_bpf rte_ipsec rte_cfgfile rte_gro rte_gso rte_hash rte_member rte_kvargs rte_mbuf rte_net rte_ethdev rte_bbdev rte_cryptodev rte_security rte_compressdev rte_eventdev rte_rawdev rte_timer rte_mempool rte_stack rte_mempool_ring rte_ring rte_pci rte_eal rte_cmdline rte_reorder rte_sched rte_rcu rte_bus_pci rte_bus_vdev rte_mempool_bucket rte_mempool_stack rte_common_mlx5 rte_pmd_mlx5 ibverbs mlx5 rte_bus_ifpga numa rt m dl)

message(STATUS "Initial CMAKE_C_FLAGS=${CMAKE_C_FLAGS}")

# Set GCC as compiler
# set(CMAKE_C_COMPILER "gcc")
set(CMAKE_C_FLAGS "-std=gnu99 -O1 -ggdb -g -Wextra -Wall -Wno-deprecated-declarations -flto -ffat-lto-objects -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_RDSEED -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2 -I/etinfo/users/2021/delzotti/dma_descriptors/HOST/dpdk/XCHG_NIKITA/build/include -DRTE_USE_FUNCTION_VERSIONING -I/etinfo/users/2021/delzotti/xchange/x86_64-native-linux-gcc/include -include /etinfo/users/2021/delzotti/xchange/x86_64-native-linux-gcc/include/rte_config.h -D_GNU_SOURCE -gdwarf -O2 -ggdb -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wdeprecated -fcommon -Wno-missing-field-initializers -Wimplicit-fallthrough=2 -Wno-format-truncation -Wno-address-of-packed-member -Wno-unused-parameter -DWITH_XCHG -DFAKE_DPDK_MODE_DPDK_ASQ -DFAKE_DPDK_DESC_IP_SRC -DFAKE_DPDK_DESC_IP_DST -DFAKE_DPDK_DESC_PORT_DST -DFAKE_DPDK_DESC_PORT_SRC -DFAKE_DPDK_DESC_IP_PROTO -DFAKE_DPDK_DESC_ETH_TYPE -DALLOW_EXPERIMENTAL_API -DFAKE_DPDK_MODE_DPDK_ASQ -DXCHG  ${CMAKE_C_FLAGS}")

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
# Create variable for XCGH libary path
set(XCHG_PATH $ENV{RTE_SDK}/$ENV{RTE_TARGET}/lib)

# Create the libxchg_additional library with additional functions for xchange
ADD_LIBRARY(libxchg_additional STATIC ./xchg.c ../../../utils/asq_descriptors.h)
set_target_properties(libxchg_additional PROPERTIES COMPILE_FLAGS "-mssse3 -ggdb -mcrc32 -m64")
target_include_directories(libxchg_additional PRIVATE $ENV{RTE_SDK}/$ENV{RTE_TARGET}/include)
TARGET_LINK_LIBRARIES(libxchg_additional -L${XCHG_PATH} ${XCHG_LIBRARIES})

# Setup final executable
SET(LIBRARIES ${LIBRARIES} libxchg_additional)
set(LIBRARIES ${LIBRARIES} ${XCHG_LIBRARIES})
SET(LIBRARIES ${LIBRARIES} rt dl numa pthread curl)
add_executable(xchg_nikita
    server.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../utils/MACaddress.c
)
# Set WITH_XCHG flag
set_target_properties(xchg_nikita PROPERTIES COMPILE_DEFINITIONS "WITH_XCHG")
# Compile with ssse3
set_target_properties(xchg_nikita PROPERTIES COMPILE_FLAGS "-O1 -mssse3 -mcrc32 -ggdb -m64")
# Include XCHG headers
target_include_directories(xchg_nikita PRIVATE $ENV{RTE_SDK}/$ENV{RTE_TARGET}/include)
# Link with XCHG libraries with whole-archive
TARGET_LINK_LIBRARIES(xchg_nikita -L${XCHG_PATH} -Wl,--whole-archive ${LIBRARIES} -Wl,--no-whole-archive)
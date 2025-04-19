
# CXX flags
add_compile_options(-m64 -O3 -march=native -g -pedantic-errors
                    -Wall -Wextra -Werror -Wno-pedantic)

find_package(PkgConfig REQUIRED)
# dpdk
pkg_check_modules(LIBDPDK REQUIRED libdpdk)
# Includes
include_directories(.)

# Enso must be installed for this to work.


link_libraries(pthread)

add_executable(
    dpdk_maglev
    dpdk_maglev.cpp
)

add_executable(
    asni_maglev
    dpdk_maglev.cpp
)

add_executable(
    asni_maglev_no_tx
    dpdk_maglev.cpp
)
add_executable(
    test_maglev
    test_maglev.cpp
)
add_executable(
    asni_maglev_offload_tx
    dpdk_maglev.cpp
)

add_executable(
    asni_maglev_offload_tx_no_strip
    dpdk_maglev.cpp
)

target_compile_options(asni_maglev PRIVATE ${LIBDPDK_CFLAGS})
target_compile_options(dpdk_maglev PRIVATE ${LIBDPDK_CFLAGS})
target_link_libraries(asni_maglev ${LIBDPDK_LDFLAGS})
target_link_libraries(dpdk_maglev ${LIBDPDK_LDFLAGS})

target_compile_options(test_maglev PRIVATE ${LIBDPDK_CFLAGS})
target_link_libraries(test_maglev ${LIBDPDK_LDFLAGS})

target_compile_options(asni_maglev_no_tx PRIVATE ${LIBDPDK_CFLAGS})
target_link_libraries(asni_maglev_no_tx ${LIBDPDK_LDFLAGS})


target_compile_options(asni_maglev_offload_tx PRIVATE ${LIBDPDK_CFLAGS})
target_link_libraries(asni_maglev_offload_tx ${LIBDPDK_LDFLAGS})


target_compile_options(asni_maglev_offload_tx_no_strip PRIVATE ${LIBDPDK_CFLAGS})
target_link_libraries(asni_maglev_offload_tx_no_strip ${LIBDPDK_LDFLAGS})

target_include_directories(asni_maglev PRIVATE ${CMAKE_SOURCE_DIR}/../../../utils)
target_include_directories(asni_maglev_no_tx PRIVATE ${CMAKE_SOURCE_DIR}/../../../utils)
target_include_directories(asni_maglev_offload_tx PRIVATE ${CMAKE_SOURCE_DIR}/../../../utils)
target_include_directories(asni_maglev_offload_tx_no_strip PRIVATE ${CMAKE_SOURCE_DIR}/../../../utils)

set_target_properties(asni_maglev PROPERTIES COMPILE_FLAGS "-DASNI -DFAKE_DPDK_MODE_DPDK_ASQ -DFAKE_DPDK_DESC_SIZE -fcommon")

set_target_properties(asni_maglev_offload_tx PROPERTIES COMPILE_FLAGS "-DASNI -DFAKE_DPDK_MODE_DPDK_ASQ -DFAKE_DPDK_DESC_SIZE -fcommon -DOFFLOAD_TX -DSTRIP_DESCRIPTORS")

set_target_properties(asni_maglev_offload_tx_no_strip PROPERTIES COMPILE_FLAGS "-DASNI -DFAKE_DPDK_MODE_DPDK_ASQ -DFAKE_DPDK_DESC_SIZE -fcommon -DOFFLOAD_TX")

set_target_properties(asni_maglev_no_tx PROPERTIES COMPILE_FLAGS "-DASNI -DFAKE_DPDK_MODE_DPDK_ASQ -DFAKE_DPDK_DESC_SIZE -DDISABLE_TX -fcommon")

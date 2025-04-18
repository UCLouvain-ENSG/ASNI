cmake_minimum_required(VERSION 3.22)
project(vignat)

# If the XCHG flag is set, include `cmake_xchg/CMakelists.txt`
if (XCHG)
    include(cmake_xchg/CMakeLists.txt)
elseif (DPDK)
    include(cmake_dpdk/CMakeLists.txt)
elseif (ASNI_OFFLOAD_TX)
    include(cmake_asni_offload_tx/CMakeLists.txt)
else()
    message(FATAL_ERROR "No build type specified. Please specify either -DXCHG=ON or -DDPDK=ON")
endif()

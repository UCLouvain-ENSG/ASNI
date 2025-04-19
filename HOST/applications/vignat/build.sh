#!/usr/bin/bash

echo "Building Vignat"
echo "================"
echo "RTE_SDK: $RTE_SDK"
echo "RTE_TARGET: $RTE_TARGET"
echo "PKG_CONFIG_PATH: $PKG_CONFIG_PATH"
echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
echo "================"

# Build XCHG
# echo "Building with XCHG"
# cmake -DXCHG=ON -Bbuild_xchg
# make -C build_xchg
# echo "================"

# Build DPDK
echo "Building with DPDK"
cmake -DDPDK=ON -Bbuild_dpdk
make -C build_dpdk
echo "================"

# Build ASNI
echo "Building with ASNI_OFFLOAD_TX"
cmake -DASNI_OFFLOAD_TX=ON -Bbuild_asni_offload_tx
make -C build_asni_offload_tx
echo "================"

echo "Build complete"

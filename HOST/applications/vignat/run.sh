#!/bin/bash
# Ensure that the script is run as root
if [ "$EUID" -ne 0 ]; then
	echo "Did you really expect to control the NIC without root privileges?"
	exit
fi

# Setup env variables
export RTE_SDK=/etinfo/users/2021/delzotti/dpdk/install
export LD_LIBRARY_PATH=/etinfo/users/2021/delzotti/dpdk/install/lib/x86_64-linux-gnu:/etinfo/users/2021/delzotti/dpdk/install/lib/x86_64-linux-gnu:
export PKG_CONFIG_PATH=/etinfo/users/2021/delzotti/dpdk/install/lib/x86_64-linux-gnu/pkgconfig:/opt/mellanox/grpc/lib/pkgconfig:/opt/mellanox/doca/lib/x86_64-linux-gnu/pkgconfig
echo $RTE_SDK
echo $LD_LIBRARY_PATH
echo $PKG_CONFIG_PATH
# Run app
gdb --args ./build/vignat -l 0 -n 3 --proc-type primary -a 0000:51:00.0 -a 0000:51:00.1 -- $2
# /etinfo/users/2021/delzotti/dpdk/install/bin/dpdk-test -a 0000:18:00.1 --proc-type primary

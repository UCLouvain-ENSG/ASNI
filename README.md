# ASNI : Application Specific Network Interface

ASNI argues in favor of changing the way the NIC delivers packets instead of using drivers (in the datapath) to translate packets between the NIC and the application.
ASNI aims to solve the fundamentally mismatch between the way packets are transmitted to the CPU (inside per-packet scattered buffers) and the way that the CPU wants to process them (continuous arrays of packets).
We implemented ASNI on the NVIDIA BlueField-3 SmartNIC.
We explored multiple implementation design, while some of them rely on a proprietary API the final design is built on top of DPDK for both the SmartNIC and the host, meaning that it could be ported to other platforms. 

## Requirements

ASNI was tested with Ubuntu 22.04 kernel 5.15, DPDK 23.03 and DOCA 2.7 and requires an NVIDIA BlueField-2 or BlueField-3. 
ASNI was tested on both, altough more extensive tests and measurements were performed on the BlueField-3.

## Compiling and Using ASNI

ASNI is composed of two components. 
One executable on the NIC that receives packets and transmits large Ethernet frames to the host. The code is available [here](NIC/dpdk/ASNI/client.c).   
To enable or disable features, ASNI relies on compilations flags, the provided [meson.build](NIC/dpdk/ASNI/meson.build) file is a good resource to understand how the different compilation flags work together.
A [script](NIC/dpdk/ASNI/fullmake.sh) is provided to compile all the ASNI variants.

The second component is a library on the host that abstracts the different abstractions.

The ASNI descriptor is defined [here](utils/asni_descriptors.h).

To understand how to use this library you can look into two of the provided applications : [FloWatcher](HOST/applications/FloWatcher-DPDK/run_to_completion/floWatcher.c)  and [Vignat](HOST/applications/vignat/src/nf.c).


With some version of ASNI, packets don't transit through the ARM, but are send directly to the host instead. Those versions require a dedicated DPDK version, that exposes some additional features. 
It is available [here](https://github.com/ntyunyayev/dpdk/tree/payload_to_host_2303). 


## Running a simple example

Here are simple steps to run FloWatcher with ASNI.

On the NIC 

```console
cd $PATH_TO_ASNI/NIC/dpdk/ASNI
# This sync the ASNI repo from the host
# It is handy for developpement, you should update the first line of the script to match your setup
bash fullmake.sh
sudo  ./build_doca_dpdk/client_asni_floWatcher_base -l 0-${NB_CORES}  -a 0000:03:00.0,representor=[0,65535]
```

On the host

```console
cd $PATH_TO_ASNI/HOST/applications/FloWatcher-DPDK/run_to_completion
bash fullmake.sh
sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH  ./build/asni_dd_floWatcher_base -l 0-1 -a $PORT_PCIE_ADDR -- -s $NIC_MAC_ADDR

```


## Citing ASNI

TODO once published

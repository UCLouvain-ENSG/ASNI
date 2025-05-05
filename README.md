ASNI : Application Specific Network Interface
=============================================

ASNI argues in favor of changing the way the NIC delivers packets instead of using drivers (in the datapath) to translate packets between the NIC and the application.
ASNI is implemented on the BlueField-3 SmartNIC. We explored multiple implementation design, while some of them rely on a proprietary API. However, the final design relies purely on DPDK, meaning that it could be ported to other SmartNICs. 



Using ASNI
-------

ASNI is composed of two components. 
One executable on the NIC that receives packets and transmits large Ethernet frames to the host. The code is available [here](NIC/dpdk/ASQ/client.c).   
To enable or disable features, ASNI relies on compilations flags, the provided [meson.build](NIC/dpdk/ASQ/meson.build) file is a good resource to understand how the different compilation flags work together.
A [script](NIC/dpdk/ASQ/fullmake.sh) is provided to compile all the ASNI variants.

The second component is a library on the host that abstracts the different abstractions.

To understand how to use this library you can look into two of the provided applications : [FloWatcher](HOST/applications/FloWatcher-DPDK/run_to_completion/floWatcher.c)  and [Vignat](HOST/applications/vignat/src/nf.c).


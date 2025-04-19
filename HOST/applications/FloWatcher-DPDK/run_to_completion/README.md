# FloWatcher-DPDK
A DPDK software traffic monitor for per-flow statistics. We aim at providing the detailed statistics on both packet level and flow level. Specifically, FloWatcher-DPDK aims at providing per-flow throughput, inter-packet gap and percentiles. 

## Compiling the APP: 

### On the SMARTNIC

To compile the versions that don't require the patched DPDK, we can use the following commands:

```bash
cd ${REPO_PATH}/NIC/dpdk/ASQ
rm -r build_doca_dpdk ; meson -Dexec_type=doca_dpdk build_doca_dpdk &&  ninja -C build_doca_dpdk
```


### On the HOST
```bash
cd ${REPO_PATH}/HOST/applications/FloWatcher-DPDK/run_to_completion
meson build --wipe && ninja -C build
```


## Usage:
The best ressource to see how to run the different version is the ${REPO_PATH}/measurements/flowatcher_full.npf file. Here is an example of how to run the HW version.

### SMARTNIC 

```bash
cd ${REPO_PATH}/NIC/dpdk/ASQ
sudo ./build_doca_dpdk/client_hw_floWatcher -l 0-7 -a 0000:03:00.0,representor=[0,65535],dv_flow_en=2 -a 0000:03:00.1,representor=[0,65535] -- -c 7 -t 1
```
### HOST

```bash
cd ${REPO_PATH}/HOST/applications/FloWatcher-DPDK/run_to_completion
sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH  ./build/hw_dp_floWatcher_cycles -l 0-1 -a ${SECOND_PORT_OF_BF} -- -s 08:c0:eb:d1:fb:26
```

## Remarks

When using the the HW variants, it is necessary to use 2 ports on the SMARTNIC. The first port is used to receive the packets and the second port is used to send the packets to the HOST. This may no be necessary but I didn't manage to send packet to the host from ports where dv_flow_en=2 is set.


  

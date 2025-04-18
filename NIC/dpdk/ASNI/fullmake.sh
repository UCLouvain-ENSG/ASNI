#SYNCING !
rsync -a tyunyayev@10.0.0.1:Workspace/ASNI_repo ~/
#COMPILING
rm -r build_patched_dpdk ; LDFLAGS="-Wl,--copy-dt-needed-entries" PKG_CONFIG_PATH=$PATCHED_PKG_CONFIG_PATH LD_LIBRARY_PATH=$PATCHED_LD_LIBRARY_PATH meson -DHOME=$HOME -Dexec_type=patched_dpdk build_patched_dpdk --wipe && LD_LIBRARY_PATH=$PATCHED_LD_LIBRARY_PATH PKG_CONFIG_PATH=$PATCHED_PKG_CONFIG_PATH ninja -C build_patched_dpdk
rm -r build_doca_dpdk ; meson -DHOME=$HOME -Dexec_type=doca_dpdk build_doca_dpdk --wipe &&  ninja -C build_doca_dpdk

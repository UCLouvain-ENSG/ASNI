rsync -a tyunyayev@10.0.0.1:Workspace/ASNI ~/
LD_LIBRARY_PATH=$PATCHED_LD_LIBRARY_PATH
PKG_CONFIG_PATH=$PATCHED_PKG_CONFIG_PATH
meson build --wipe
ninja -C build

export PKG_CONFIG_PATH=/etinfo/users2/tbarbette/workspace/xchg-23.11/install/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/etinfo/users2/tbarbette/workspace/xchg-23.11/install/lib/x86_64-linux-gnu/:$LD_LIBRARY_PATH
meson build --wipe
ninja -C build

echo $LD_LIBRARY_PATH
echo $PKG_CONFIG_PATH
meson build --wipe && ninja -C build
LD_LIBRARY_PATH=/etinfo/users2/tyunyayev/Workspace/xchange23/install_atchoum/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH \
PKG_CONFIG_PATH=/etinfo/users2/tyunyayev/Workspace/xchange23/install_atchoum/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH \
meson build_xchg -Db_lto=true -DDPDK_VER=XCHG --wipe  && ninja -C build_xchg


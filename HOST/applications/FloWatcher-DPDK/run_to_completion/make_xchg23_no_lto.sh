# Compiling xchange without LTO (this should only be used for debugging)
/etinfo/users2/tyunyayev/Workspace/xchange23/install_no_lto_atchoum/lib/x86_64-linux-gnu/pkgconfig
LD_LIBRARY_PATH=/etinfo/users2/tyunyayev/Workspace/xchange23/install_atchoum_no_lto/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH \
    PKG_CONFIG_PATH=/etinfo/users2/tyunyayev/Workspace/xchange23/install_atchoum_no_lto/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH \
    meson build_xchg_no_lto --wipe -DDPDK_VER=XCHG && ninja --verbose -C build_xchg_no_lto

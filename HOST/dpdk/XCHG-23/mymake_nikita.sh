# Compiling standard xchange
LD_LIBRARY_PATH=/etinfo/users2/tyunyayev/Workspace/xchange23/install_atchoum/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH \
    PKG_CONFIG_PATH=/etinfo/users2/tyunyayev/Workspace/xchange23/install_atchoum/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH \
    meson build_xchg  && ninja --verbose -C build_xchg

# Compiling xchange without LTO (this should only be used for debugging)
LD_LIBRARY_PATH=/etinfo/users2/tyunyayev/Workspace/xchange23/install_atchoum_no_lto/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH \
    PKG_CONFIG_PATH=/etinfo/users2/tyunyayev/Workspace/xchange23/install_atchoum_no_lto/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH \
    meson build_xchg_no_lto  && ninja --verbose -C build_xchg_no_lto


export RTE_SDK=/etinfo/users2/tyunyayev/Workspace/xchange
export RTE_TARGET=x86_64-native-linux-gcc

make clean && make
meson build && ninja -C build

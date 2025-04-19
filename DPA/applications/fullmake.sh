rsync -a tyunyayev@10.0.0.1:Workspace/ASNI ~/
meson /tmp/build  --wipe
ninja -C /tmp/build

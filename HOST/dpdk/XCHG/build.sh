#!/bin/bash
set -e
for cycle in $(seq 0 1) ; do
    echo "Compiling cycles $cycle..."
    make VER=minimal CYCLES=$cycle
    make VER=minimal NOCQE=1 CYCLES=$cycle
    make VER=minimal NOCQE=1 RTC=1 CYCLES=$cycle
    make NOCQE=1 CYCLES=$cycle
    make CYCLES=$cycle
done

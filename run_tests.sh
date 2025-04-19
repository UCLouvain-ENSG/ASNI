#!/bin/bash
python3 ~/workspace/npf/npf-compare.py \
    "local+dpdk,nobf,RX_VEC_EN=1,CQE_COMP=1:DPDK" \
    "local+xchg,nobf:X-Change" \
    "local+asq,minimal:ASNI/DPDK" \
    "local+xchg,asq,minimal:ASNI/X-Change" \
    "local+xchg,asq,minimal,nortc:ASNI/X-Change (Non-RTC, Buffering)" \
    --test measurements/test.npf --cluster smartnic=bluefield server=elrond,nic=2 client=frodo,nic=1 --tags cores --show-cmd \
    --tags udpgen prate dormeur gen_norx gen_nolat cycles rate \
    --variables GEN_THREADS=8 PKT_SIZE=64 "NB_CORE=8" "SERVER_CORE=1" FNT=DROP GEN_RATE=96000000 LIMIT_TIME=10 SAMPLE=1000 LIMIT=1000000000 "CQE_COMP=0" RX_VEC_EN=0 "SM_BURST=32" \
    --config n_runs=5 "graph_max_cols=1" graph_background=1 graph_type=barplot \
    --config graph_type=barplot "var_format={result:%d}" "var_lim={CYCLES-PER-PACKET:0-160}" "graph_show_values=1" "var_names+={version:RX model}" --graph-size 6 3 \
    --graph-filename measurements/motivation/motivation_dagstuhl.svg \
    --single-output measurements/motivation/motivation_dagstuhl.csv \
    $@

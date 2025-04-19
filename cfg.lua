package.path = package.path ..";/etinfo/users2/tyunyayev/workspace/Pktgen-DPDK/?.lua"
require "Pktgen"
--pktgen.screen("off");
local dstip = "10.100.0.100"
local srcip = "10.100.0.2"
local dstmac = "08:c0:eb:bf:ef:8e"
local srcmac = "50:6b:4b:f3:7c:80"
local elephant_base_port = 8000
local elephant_dst_port = 8000

pktgen.clr();

pktgen.latency('0', 'enable');
pktgen.ports_per_page(1);

pktgen.range.dst_mac("all", "start", dstmac);
pktgen.range.src_mac("all", "start", srcmac);
pktgen.range.src_ip("all", "start", srcip);
pktgen.range.dst_ip("all", "start", dstip);

pktgen.set_range("all", "on");

pktgen.range.ip_proto("all","tcp");
pktgen.range.dst_port("0", "start", elephant_dst_port);
pktgen.range.pkt_size("0", "start", 64);
pktgen.start("0");
pktgen.delay(5000);
pktgen.stop("0");

prints("SendPort", pktgen.pktStats(0));
local port_stats = pktgen.pktStats(0);

printf("Number of latency packets on port %d : %d\n",
    0, port_stats[0].latency.num_pkts);

pktgen.portStats(0,"ports");
pktgen.quit();

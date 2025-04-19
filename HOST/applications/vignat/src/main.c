/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

// #ifdef FAKE_DPDK_IO_XCHG
// #define   RTE_BIT64(nr)                       (UINT64_C(1) << (nr))
// #define 	RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE   RTE_BIT64(16)
// #define RTE_ETHER_ADDR_BYTES(mac_addrs) ((mac_addrs)->addr_bytes[0]), \
//                     ((mac_addrs)->addr_bytes[1]), \
//                     ((mac_addrs)->addr_bytes[2]), \
//                     ((mac_addrs)->addr_bytes[3]), \
//                     ((mac_addrs)->addr_bytes[4]), \
//                     ((mac_addrs)->addr_bytes[5])
// #define SKIP_MAIN SKIP_MASTER
// #endif

#include "main.h"

// struct rte_mempool *mbuf_pool;

// #define RX_RING_SIZE 1024
// #define TX_RING_SIZE 1024

// #define RTE_HUGE_MBUF_SIZE 32768

// #define NUM_MBUFS 32767
// #define NUM_HUGE_MBUFS 8191
// #define MBUF_CACHE_SIZE 256
// #define BURST_SIZE 32

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

// /*
//  * Initializes a given port using global settings and with the RX buffers
//  * coming from the mbuf_pool passed as a parameter.
//  */

// /* Main functional part of port initialization. 8< */
// static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
//   struct rte_eth_conf port_conf;
//   const uint16_t rx_rings = 1, tx_rings = 1;
//   uint16_t nb_rxd = RX_RING_SIZE;
//   uint16_t nb_txd = TX_RING_SIZE;
//   int retval;
//   uint16_t q;
//   struct rte_eth_dev_info dev_info;
//   struct rte_eth_txconf txconf;

//   if (!rte_eth_dev_is_valid_port(port))
//     return -1;

//   memset(&port_conf, 0, sizeof(struct rte_eth_conf));

//   retval = rte_eth_dev_info_get(port, &dev_info);
//   if (retval != 0) {
//     printf("Error during getting device (port %u) info: %s\n", port,
//            strerror(-retval));
//     return retval;
//   }

//   if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
// #ifdef FAKE_DPDK_IO_DPDK
//     port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE | RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
// #endif
// #ifdef FAKE_DPDK_IO_XCHG
//     port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE | DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM;
// #endif
//   /* Configure the Ethernet device. */
//   retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
//   if (retval != 0)
//     return retval;

//   retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
//   if (retval != 0)
//     return retval;

//   /* Allocate and set up 1 RX queue per Ethernet port. */
//   for (q = 0; q < rx_rings; q++) {
//     retval = rte_eth_rx_queue_setup(
//         port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
//     if (retval < 0)
//       return retval;
//   }

//   txconf = dev_info.default_txconf;
//   txconf.offloads = port_conf.txmode.offloads;
//   /* Allocate and set up 1 TX queue per Ethernet port. */
//   for (q = 0; q < tx_rings; q++) {
//     retval = rte_eth_tx_queue_setup(port, q, nb_txd,
//                                     rte_eth_dev_socket_id(port), &txconf);
//     if (retval < 0)
//       return retval;
//   }

//   /* Starting Ethernet port. 8< */
//   retval = rte_eth_dev_start(port);
//   /* >8 End of starting of ethernet port. */
//   if (retval < 0)
//     return retval;

//   /* Display the port MAC address. */
//   struct rte_ether_addr addr;
//   retval = rte_eth_macaddr_get(port, &addr);
//   if (retval != 0)
//     return retval;

//   printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
//          " %02" PRIx8 " %02" PRIx8 "\n",
//          port, RTE_ETHER_ADDR_BYTES(&addr));

//   /* Enable RX in promiscuous mode for the Ethernet device. */
//   retval = rte_eth_promiscuous_enable(port);
//   /* End of setting RX port in promiscuous mode. */
//   if (retval != 0)
//     return retval;

//   return 0;
// }
// /* >8 End of main functional part of port initialization. */


// In case DPDK fucks up, we might want to check if it still works with a simple application
#ifdef DUMMY_DPDK
/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static 
#ifdef WITH_DPDK
__rte_noreturn 
#elif defined(WITH_XCHG)
__attribute__((noreturn))
#endif
void lcore_main(void) {
  uint16_t port = 0;
  printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());

  /* Main work of application loop. 8< */
  for (;;) {
    struct rte_mbuf *bufs[BURST_SIZE];
    const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

    if (unlikely(nb_rx == 0))
      continue;

    for (uint16_t buf = 0; buf < nb_rx; buf++) {
      printf("Packet received.\n");
      // Retrieve pointer to packet data.
      // uint8_t *buffer = rte_pktmbuf_mtod(bufs[buf], uint8_t *);
      // // Retrieve packet length.
      // uint16_t packet_length = rte_pktmbuf_pkt_len(bufs[buf]);
      // // Retrieve current time.
      // vigor_time_t now = current_time();
      // // Process packet.
      // nf_process(0, buffer, packet_length, now);
      rte_pktmbuf_free(bufs[buf]);
    }
  }
  /* >8 End of loop. */
}
/* >8 End Basic forwarding application lcore. */

#endif

// uint8_t in(uint16_t val, uint16_t *arr, uint16_t len) {
//   for (uint16_t i = 0; i < len; i++) {
//     if (arr[i] == val)
//       return 1;
//   }
//   return 0;
// }

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[]) {
  return fake_io_launch(argc, argv, worker_main);
//   unsigned nb_ports = ENABLED_PORTS_LEN;
//   uint16_t portid;

//   /* Initializion the Environment Abstraction Layer (EAL). 8< */
//   int ret = rte_eal_init(argc, argv);
//   if (ret < 0)
//     rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
//   /* >8 End of initializion the Environment Abstraction Layer (EAL). */

//   argc -= ret;
//   argv += ret;

//   /* Creates a new mempool in memory to hold the mbufs. */

// #ifdef FAKE_DPDK_IO_DPDK
//   printf("Using DPDK\n");
//   /* Allocates mempool to hold the mbufs. 8< */
//   mbuf_pool = rte_pktmbuf_pool_create(
//       "MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
//       RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
//   /* >8 End of allocating mempool to hold mbuf. */
// #elif defined(FAKE_DPDK_IO_XCHG)
//   printf("Using XCHG\n");
//   mbuf_pool = rte_pktmbuf_pool_create(
//             "MBUF_POOL", NUM_HUGE_MBUFS, MBUF_CACHE_SIZE, 0, RTE_HUGE_MBUF_SIZE,
//             rte_socket_id());
// #endif

//   /* Initializing all ports. 8< */
//   uint16_t ports[] = ENABLED_PORTS;
//   RTE_ETH_FOREACH_DEV(portid){
//     if (in(portid, ports, ENABLED_PORTS_LEN)){
//       if (port_init(portid, mbuf_pool) != 0){
//         rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
//       } else {
//         printf("Sucessfully initialized port %" PRIu16 "\n", portid);
//       }
//     } else {
//       printf("Skipping port %" PRIu16 " \n", portid);
//     }
//   }
//   /* >8 End of initializing all ports. */


// #ifdef DUMMY_DPDK
//   rte_eal_mp_remote_launch((int (*)(void *))lcore_main, NULL, 1);
// #elif defined(FAKE_DPDK_IO_XCHG)
//   // print each available core
//     // rte_eal_remote_launch((int (*)(void *))worker_main, NULL, 0);
//   rte_eal_mp_remote_launch((int (*)(void *))worker_main, NULL, CALL_MASTER);
// #elif defined(FAKE_DPDK_IO_DPDK)
//   rte_eal_mp_remote_launch((int (*)(void *))worker_main, NULL, SKIP_MAIN);
// #endif

//   /* clean up the EAL */
//   rte_eal_cleanup();

//   return 0;
}

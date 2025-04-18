/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include "consts.h"
#include "dpdk_utils2.h"
#include <getopt.h>
#include <inttypes.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
//#include <../../../utils/port_init.h>

#define RX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define NUM_PORTS 1

static volatile bool force_quit = false;

struct custom_header {
    char padding1[2];
    uint32_t length;
    char padding2[2];
    uint32_t dst_ip;
} __attribute__((packed));
/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */

static void
signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM || signum == SIGKILL) {
        printf("\n\nSignal %d received, preparing to exit\n", signum);

        struct rte_eth_stats stats = {0};

        // Get port stats
        struct rte_eth_stats new_stats;
        rte_eth_stats_get(0, &new_stats);
        // Print stats
        printf("before print\n");
        printf("\nNumber of received packets : %ld"
               "\nNumber off missed packets : %ld"
               "\nNumber of queued RX packets : %ld"
               "\nNumber of dropped queued packet : %ld"
               "\nNumber of erroneous received packets : %ld\n\n",
               new_stats.ipackets, new_stats.imissed, new_stats.q_ipackets[0], new_stats.q_errors[0], new_stats.ierrors);

        force_quit = true;
    }
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

/* Basic forwarding application lcore. 8< */
static int
lcore_main(uint16_t port) {
    uint64_t port_stats = 0;

    unsigned id = 0;

    /*
         * Check that the port is on the same NUMA node as the polling thread
         * for best performance.
         */
    if (rte_eth_dev_socket_id(port) >= 0 &&
        rte_eth_dev_socket_id(port) != (int)rte_socket_id())
        printf("WARNING, port %u is on remote NUMA node to "
               "polling thread.\n\tPerformance will "
               "not be optimal.\n",
               port);

    printf("\nCore %u counting incoming packets from queue %d, port %d. [Ctrl+C to quit]\n",
           rte_lcore_id(), id, port);

    int counter = 0;
    int index;
    uint64_t start = 0;
    uint64_t end = 0;
    uint64_t nb_byte = 0;

    struct rte_mbuf *bufs[BURST_SIZE];
    struct rte_ipv4_hdr *ip_hdr;
    uint32_t ip_dst = 0;
    uint32_t ip_src = 0;

    uint64_t start_cycle = 0;
    uint64_t end_cycle = 0;
    uint64_t rte_burst = 0;
    uint64_t miss_rte_burst = 0;
    uint64_t pkt_analysis = 0;
    uint64_t total_length = 0;
    uint64_t curr_tot = 0;
    struct custom_header *ch;

    /* Main work of application loop. 8< */
    for (;;) {
        if (force_quit) {
            end = rte_get_tsc_cycles();
            double time_elapsed = (double)(end - start) / rte_get_tsc_hz();
            printf("RESULT-THROUGHPUT %fGbps", (nb_byte * 8 / time_elapsed) / 1000000000);
            printf("\nReceived %d packets in %f seconds : throughput : %fGb/s\n"
                   "rte_burst cycle : %ld, pkt_analysis cycle : %ld\n",
                   counter, time_elapsed, (nb_byte * 8 / time_elapsed) / 1000000000, rte_burst, pkt_analysis);

            printf("\nReceived a total of %d packets in %f seconds\n", counter, (double)(end - start) / rte_get_tsc_hz());
            return 0;
        }

        
        /* Get burst of RX packets, from first port of pair. */
        const uint16_t nb_rx = rte_eth_rx_burst(port, id, bufs, BURST_SIZE);

        if (nb_rx == 0)
            continue;
        //printf("pkt_received\n");
        int dummy_counter = 0;
        for (int i = 0; i < nb_rx; i++) {
            // if (RTE_ETH_IS_IPV4_HDR(bufs[i]->packet_type)) {
                //printf("inside\n");
                // ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(bufs[i], char *) +
                //                                  sizeof(struct rte_ether_hdr));
                // if(ip_hdr->dst_addr % 2 == 0){
                //     dummy_counter++;
                // }
                dummy_counter+=ip_hdr->dst_addr;
                //printf("bufs[i]->pkt_len : %d\n", bufs[i]->pkt_len);
                nb_byte+=bufs[i]->pkt_len;
                //printf("nb_bytes : %ld\n", nb_byte);
            // }
            // else{
            //     printf("outside : %d\n");
            // }
        }
        rte_pktmbuf_free_bulk(bufs, nb_rx);
        // end_cycle = rte_get_tsc_cycles();
        // rte_burst += (end_cycle - start_cycle);

        if (start == 0)
            start = rte_get_tsc_cycles();

        // port_stats += nb_rx;

        // start_cycle = rte_get_tsc_cycles();
        // /* Do a small job on each descriptor on the ip field */
        // for (index = 0; index < nb_rx; index++) {
        //     counter++;
        //     nb_byte += bufs[index]->data_len;

        //     /* if this is an IPv4 packet */
        //     if (RTE_ETH_IS_IPV4_HDR(bufs[index]->packet_type)) {
        //         /* Load balancer changes destination ip*/
        //         ip_hdr = rte_pktmbuf_mtod_offset(bufs[index], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
        //         ip_hdr->dst_addr = ip_hdr->dst_addr + 1;

        //     } else {
        //         printf("\nIP header doesn't match IPV4 type\n");
        //     }
        //     rte_pktmbuf_free(bufs[index]);
        // }
        // int pkts_sent = rte_eth_tx_burst(port, id, bufs, nb_rx);
        // if (pkts_sent != nb_rx) {
        //     rte_pktmbuf_free_bulk(&(bufs[pkts_sent]), (nb_rx - pkts_sent) + 1);
        // }
        // /* Free all received packets. */

        // end_cycle = rte_get_tsc_cycles();
        // pkt_analysis += (end_cycle - start_cycle);

        // end = rte_get_tsc_cycles();
    }
}

struct rte_ether_addr macAddr1;
int nb_core = 1;
int option(int argc, char **argv) {

    int c;
    int s = -1;

    while (1) {

        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "c:", 0, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) {

        case 'c':
            nb_core = atoi(optarg);
            break;

        case '?':
            /* getopt_long already printed an error message. */
            break;

        default:
            abort();
        }
    }

    // Check mandatory parameters:

    /* Print any remaining command line arguments (not options). */
    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s \n", argv[optind++]);
    }

    return 0;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[]) {
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports = 1;
    uint16_t portid = 0;
    uint16_t port = 0;

    /* Initializion the Environment Abstraction Layer (EAL). 8< */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    /* >8 End of initialization the Environment Abstraction Layer (EAL). */

    argc -= ret;
    argv += ret;

    /* Initialize the MAC addresses to count the incoming number of packets */
    ret = option(argc, argv);
    if (ret == -1)
        return -1;

    /* Creates a new mempool in memory to hold the mbufs. */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initializing the desired port. */
    if (normal_mtu_port_init(portid, mbuf_pool, 1, 1) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);

    /* Handle the Control+C */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    uint16_t lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_remote_launch(lcore_main, NULL, lcore_id);
        break;
    }
    

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include "../../../utils/MACaddress.h"
#include "rte_errno.h"
#include <getopt.h>
#include <inttypes.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define debug(...)
// #define debug(...) printf(__VA_ARGS__)

#define HAVE_CYCLE 1

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define RTE_MBUF_SIZE 2048 + 128

#define MTU 9800
#define RTE_HUGE_MBUF_SIZE 9800 + 128

#define NUM_MBUFS 32767
#define NUM_HUGE_MBUFS 8191
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32
#define BURST_SIZE_XCHG 32
#define NUM_PORTS 1
#ifdef XCHG
#include <rte_xchg.h>
#define SKIP_MAIN SKIP_MASTER
#include "../../../utils/asq_descriptors.h"
#include "main.h"
#endif

struct rte_ether_addr macAddr1;
int nb_core = 1;
static int light = 0;
static int asq = 1;
struct rte_mempool *mbuf_pool[2];
struct rte_mempool *mbuf_pool_small[2];
static volatile bool force_quit = false;
uint64_t counter_total = 0;
uint64_t nb_sent = 0;
uint64_t tx_burst_tried = 0;
uint64_t tx_burst_failed = 0;
uint64_t breakpoints[256];
uint64_t breakpoint_index;
int option(int argc, char **argv);

int src_port = -1;
int dst_port = -1;
/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int xchg_port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    const uint16_t rx_rings = 1;
    const uint16_t tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    static struct rte_eth_conf port_conf = {

        .rxmode =
            {
#ifdef XCHG
                .offloads = DEV_RX_OFFLOAD_SCATTER,
#else
                .offloads = RTE_ETH_RX_OFFLOAD_SCATTER,
#endif
            },
        .txmode =
            {
#ifdef XCHG
                .mq_mode = ETH_MQ_TX_NONE,
                .offloads = DEV_TX_OFFLOAD_MULTI_SEGS,
#else
                .mq_mode = RTE_ETH_MQ_TX_NONE,
#endif
            },
    };

    //	static struct rte_eth_conf port_conf;
    //        memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n", port,
               strerror(-retval));
        return retval;
    }
    printf("min_mtu : %d\n", dev_info.min_mtu);
    printf("max_mtu : %d\n", dev_info.max_mtu);

    // if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
    //     port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    //     printf("fast free enabled\n");
    // }
    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (uint16_t q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(
            port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (uint16_t q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

#ifdef XCHG
    retval = rte_eth_dev_set_mtu(port, 9978);
    if (retval < 0) {
        printf("failed to set mtu\n");
        return retval;
    }
#else
    retval = rte_eth_dev_set_mtu(port, 1500);
    if (retval < 0) {
        printf("failed to set mtu\n");
        return retval;
    }
#endif
    /* Starting Ethernet port. 8< */
    retval = rte_eth_dev_start(port);
    /* >8 End of starting of ethernet port. */
    if (retval < 0) {
        printf("failed to start device\n");
        return retval;
    }
    /* Display the port MAC address. */
    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0)
        return retval;

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    /* End of setting RX port in promiscuous mode. */
    if (retval != 0)
        return retval;

    return 0;
}

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM || signum == SIGKILL) {
        printf("\n\nSignal %d received, preparing to exit\n", signum);

        static const char *stats_border = "_______";
        uint16_t portid;
        RTE_ETH_FOREACH_DEV(portid) {

            struct rte_eth_xstat *xstats;
            struct rte_eth_xstat_name *xstats_names;
            int len, ret, i;

            printf("PORT STATISTICS:\n================\n");
            len = rte_eth_xstats_get(portid, NULL, 0);
            if (len < 0)
                rte_exit(EXIT_FAILURE, "rte_eth_xstats_get(%u) failed: %d",
                         portid, len);
            xstats = calloc(len, sizeof(*xstats));
            if (xstats == NULL)
                rte_exit(EXIT_FAILURE, "Failed to calloc memory for xstats");
            ret = rte_eth_xstats_get(portid, xstats, len);
            if (ret < 0 || ret > len) {
                free(xstats);
                rte_exit(EXIT_FAILURE,
                         "rte_eth_xstats_get(%u) len%i failed: %d", portid, len,
                         ret);
            }
            xstats_names = calloc(len, sizeof(*xstats_names));
            if (xstats_names == NULL) {
                free(xstats);
                rte_exit(EXIT_FAILURE,
                         "Failed to calloc memory for xstats_names");
            }
            ret = rte_eth_xstats_get_names(portid, xstats_names, len);
            if (ret < 0 || ret > len) {
                free(xstats);
                free(xstats_names);
                rte_exit(EXIT_FAILURE,
                         "rte_eth_xstats_get_names(%u) len%i failed: %d",
                         portid, len, ret);
            }
            for (i = 0; i < len; i++) {
                if (xstats[i].value > 0)
                    printf("Port %u: %s %s:\t\t%" PRIu64 "\n", portid,
                           stats_border, xstats_names[i].name, xstats[i].value);
            }

            struct rte_eth_stats stats;
            rte_eth_stats_get(portid, &stats);
            // // Print stats
            printf("\n\n===basic stats port %d : ===\n\n", portid);
            printf("\nTotal number of successfully received packets : %ld"
                   "\nTotal of Rx packets dropped by the HW, because there are "
                   "no available buffer : %ld"
                   "\nTotal number of failed transmitted packets : %ld"
                   "\nTotal number of successfully transmitted packets : %ld",
                   stats.ipackets, stats.imissed, stats.oerrors,
                   stats.opackets);
            printf("\n\n=============================\n\n");
        }
        // Get port stats

        force_quit = true;
    }
}

// static void segfault_handler(int signum) {
//
//     if (SIGSEGV) {
//         printf("inside segfault\n");
//         int i = 0;
//         printf("received %lu packets\n", counter_total);
//         while (breakpoints[i]) {
//             printf("breakpoints[%d] : %lu\n", i, breakpoints[i]);
//             i++;
//         }
//         force_quit = true;
//         exit(EXIT_FAILURE);
//     }
// }
unsigned int find_rdtsc_overhead(void);

unsigned int find_rdtsc_overhead(void) {
    const int trials = 1000000;

    unsigned long long tot = 0;

    for (int i = 0; i < trials; ++i) {
        unsigned long long t_begin = rte_get_tsc_cycles();
        unsigned long long t_end = rte_get_tsc_cycles();
        tot += (t_end - t_begin);
    }
    return tot / trials;
}

#ifdef XCHG
static void xchg_free_large_packet(struct big_packet_metadata *metadata) {
    (metadata->refcnt)--;
    if (metadata->refcnt <= 0) {
        // printf("Freeing packets\n");
        rte_mbuf_raw_free(metadata->mb);
        rte_free(metadata);
    }
}
#endif
/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

/* Basic forwarding application lcore.*/
static int lcore_main(void *arg) {
    uint16_t port = (uintptr_t)arg;
    uint16_t qid = 0;
    // printf("struct size : %d\n", sizeof(struct descriptor));
    // printf("size of descriptor : %d\n", sizeof(struct xchg));
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

    uint64_t rdtsc_time = find_rdtsc_overhead();
    printf("RDTSC time is %lu\n", rdtsc_time);
    printf("\nProcessing incoming packets on port : %d. [Ctrl+C to quit]\n",
           port);

    // uint64_t timestamp = 0;
    uint64_t nb_byte = 0;
    uint8_t *payload;
#ifdef XCHG
    struct my_xchg pkts_burst_store[BURST_SIZE] = {0};
    struct my_xchg *pkts_burst[BURST_SIZE];
    struct my_xchg *pkts_tx_burst[BURST_SIZE];
    for (int i = 0; i < BURST_SIZE; i++) {
        pkts_tx_burst[i] = rte_zmalloc(NULL, sizeof(struct my_xchg), 0);
    }
    for (int i = 0; i < BURST_SIZE; i++) {
        pkts_burst[i] = &pkts_burst_store[i];
        pkts_burst[i]->buffer = 0;
    }
#else
    struct rte_mbuf *pkts_burst[BURST_SIZE];

#endif
    uint64_t start = 0;
    uint64_t end = 0;
#ifdef HAVE_CYCLE
    uint64_t start_cycle = 0;
    uint64_t end_cycle = 0;
#else
    uint64_t end_last = 0;
#endif

    uint64_t useful_cycles = 0;
    uint64_t useless_cycles = 0;
    /* Main work of application loop. 8< */
    for (;;) {
        if (force_quit) {
            double time_elapsed = (double)(end - start) / rte_get_tsc_hz();
            printf("RESULT-TESTTIME %f\n", time_elapsed);
            printf("RESULT-THROUGHPUT %fGbps\n",
                   (((nb_byte) * 8) / time_elapsed) / 1000000000);
            printf("RESULT-COUNT %ld\n", counter_total);
            printf("RESULT-PPS %f\n", (double)counter_total / (time_elapsed));
            printf("RESULT-FPPS %f\n", (double)nb_sent / (time_elapsed));
            printf("RESULT-RATIO-BURST-FAILED %f \n",
                   (double)(tx_burst_failed) /
                       (double)(tx_burst_tried + tx_burst_failed));
            printf("RESULT-GOODPUT %fGbps\n",
                   ((nb_byte * 8) / time_elapsed) / 1000000000);
            printf("RESULT-USEFULKCYCLES %lu\n", useful_cycles / 1000);
            if (counter_total > 0)
                printf("RESULT-CYCLES-PER-PACKET %lu\n",
                       useful_cycles / counter_total);
            if (useful_cycles + useless_cycles > 0)
                printf("RESULT-CPU-LOAD %f\n",
                       (double)useful_cycles /
                           (double)(useful_cycles + useless_cycles));
            return 0;
        }

#ifdef HAVE_CYCLE
        start_cycle = rte_get_tsc_cycles();
#endif
        /* Get burst of RX packets, from first port of pair. */

#ifdef XCHG
        const uint16_t nb_rx =
            rte_eth_rx_burst_xchg(src_port, 0, pkts_burst, BURST_SIZE);
#else
        const uint16_t nb_rx =
            rte_eth_rx_burst(src_port, 0, pkts_burst, BURST_SIZE_XCHG);
#endif

        if (nb_rx == 0) {
            continue;
            // } else {
            //     printf("pkt received : %d\n", nb_rx);
        }
        // #ifdef XCHG
        //         printf("pkt_len : %d\n", pkts_burst[0]->plen);
        // #else
        //         printf("pkt_len : %d\n", pkts_burst[0]->pkt_len);
        //         printf("data_len : %d\n", pkts_burst[0]->data_len);
        //         printf("nb_segs : %d\n", pkts_burst[0]->nb_segs);
        // #endif

#ifdef XCHG
        for (int i = 0; i < nb_rx; i++) {
            uint32_t offset_desc = 16;
            uint8_t *data = pkts_burst[i]->buffer;

            uint8_t nb_desc = *data;
            // printf("nb_desc : %d\n", nb_desc);
            payload =
                data + offset_desc + (nb_desc * sizeof(struct descriptor));
            if (unlikely(nb_desc < 1 || nb_desc > 64)) {
                printf(
                    "received packet with wrong number of descriptors : %d\n",
                    nb_desc);
            } else {
                struct big_packet_metadata *metadata =
                    rte_malloc(NULL, sizeof(struct big_packet_metadata), 0);
                if (!metadata) {
                    printf("failed to allocate struct\n");
                }
                metadata->refcnt = nb_desc;

                metadata->mb = xchg_get_mbuf(pkts_burst[i]);

                struct descriptor *desc =
                    (struct descriptor *)(data + offset_desc);
                pkts_tx_burst[0]->buffer = payload;
                pkts_tx_burst[0]->plen = desc->size;
                pkts_tx_burst[0]->metadata = metadata;
                // printf("desc->size : %d\n", desc->size);
                nb_byte += desc->size;
                counter_total++;
                for (uint8_t j = 1; j < nb_desc; j++) {
                    counter_total++;
                    desc = (struct descriptor *)(desc + 1);
                    int length = desc->size;
                    nb_byte += length;
                    payload += length;
                    pkts_tx_burst[j]->buffer = payload;
                    pkts_tx_burst[j]->plen = length;
                    pkts_tx_burst[j]->metadata = metadata;
                }
                const uint16_t sent = rte_eth_tx_burst_xchg(
                    dst_port, qid, pkts_tx_burst, nb_desc);

                for (int i = sent; i < nb_desc; i++) {
                    xchg_free_large_packet(pkts_tx_burst[i]->metadata);
                }

                // qid = (qid + 1) % BURST_SIZE;
                tx_burst_tried += nb_desc;
                if (sent != nb_desc) {
                    tx_burst_failed += (nb_desc - sent);
                }
                nb_sent += sent;
            }
            breakpoint_index = 0;

            pkts_burst[i]->buffer = 0;
        }
#else
        int nb_tx = rte_eth_tx_burst(dst_port, 0, pkts_burst, nb_rx);
        for (int i = 0; i < nb_tx; i++) {
            counter_total++;
            nb_byte += pkts_burst[i]->pkt_len;
        }
        // printf("inside else\n");
        tx_burst_tried++;
        nb_sent += nb_tx;
        if (nb_tx != nb_rx) {
            tx_burst_failed++;
            for (int i = nb_tx; i < nb_rx; i++) {
                rte_pktmbuf_free(pkts_burst[i]);
            }
        }

#endif
#ifdef HAVE_CYCLE
        if (unlikely(start == 0)) {
            start = start_cycle;
        }
#endif
        debug("Received %d packets\n", nb_rx);
        /* Do a small job on each xchg on the ip field */

#ifdef HAVE_CYCLE
        end_cycle = rte_get_tsc_cycles();
        useful_cycles += (end_cycle - start_cycle - rdtsc_time);

        end = end_cycle;
#endif
    }
}

int option(int argc, char **argv) {

    int c;
    int s = -1;

    while (1) {
        static struct option long_options[] = {
            /* These options set a flag. */
            {"light", no_argument, &light, 1},
            {"asq", no_argument, &asq, 1},

        };
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "c:", long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) {
        case 0:
            /* If this option set a flag, do nothing else now. */
            if (long_options[option_index].flag != 0)
                break;
            break;
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
    uint16_t portid = 0;
    uint16_t port = 0;

    int opt;
    struct rte_flow_error error;
    struct rte_flow *flow;
    /* Initializion the Environment Abstraction Layer (EAL). 8< */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    /* >8 End of initialization the Environment Abstraction Layer (EAL). */

    argc -= ret;
    argv += ret;

    while ((opt = getopt(argc, argv, "s:d:")) != -1) {
        switch (opt) {
        case 's':
            src_port = atoi(optarg);
            break;
        case 'd':
            dst_port = atoi(optarg);
            break;
        case '?':
            fprintf(stderr,
                    "Usage: %s -l <packet_size> -s <value> -d <value>\n",
                    argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // Check if required options are provided
    if (src_port == -1 || dst_port == -1) {
        fprintf(stderr, "Please provide values for both -s and -d options.\n");
        exit(EXIT_FAILURE);
    }
    /* Initialize the MAC addresses to count the incoming number of packets */
    // ret = option(argc, argv);
    // if (ret == -1)
    //     return -1;

    /* Creates a new mempool in memory to hold the mbufs. */

    char MBUF_POOL_NAME[128] = "X_MBUF_POOL";
    char MBUF_POOL_NAME_SMALL[128] = "X_MBUF_POOL_SMALL";
    RTE_ETH_FOREACH_DEV(portid) {
        MBUF_POOL_NAME[0] = portid + 42;
        MBUF_POOL_NAME_SMALL[0] = portid + 42;
        asq = 1;
        if (asq) {
            printf("Allocating huge pool : %d\n", RTE_HUGE_MBUF_SIZE);
            mbuf_pool[portid] = rte_pktmbuf_pool_create(
                MBUF_POOL_NAME, NUM_HUGE_MBUFS, MBUF_CACHE_SIZE, 0,
                RTE_HUGE_MBUF_SIZE, rte_socket_id());
            printf("Allocating small pool\n");
            mbuf_pool_small[portid] = rte_pktmbuf_pool_create(
                MBUF_POOL_NAME_SMALL, NUM_HUGE_MBUFS, MBUF_CACHE_SIZE, 0,
                RTE_MBUF_SIZE, rte_socket_id());
        }
        if (mbuf_pool[portid] == NULL || mbuf_pool_small[portid] == NULL)
            rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

        /* Initializing the desired port. */
        if (xchg_port_init(portid, mbuf_pool[portid]) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", 0);

        // if (xchg_port_init(1, mbuf_pool_small) != 0)
        //     rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", 1);
        //
        if (rte_lcore_count() > 1)
            printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

        if (nb_core != 1)
            printf("Only supports one core.\n");
        printf("\nListening on port : %d.\n", port);
    }

    /* Handle the Control+C */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    // signal(SIGSEGV, segfault_handler);
    rte_eal_mp_remote_launch(lcore_main, (void *)(uintptr_t)port, SKIP_MAIN);

    rte_eal_mp_wait_lcore();

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}

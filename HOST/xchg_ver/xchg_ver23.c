/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */
#include "xchg_ver23.h"
#include "../../../utils/MACaddress.h"
#include "dgu_utils.h"
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

#define XCHG 1

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define RTE_MBUF_SIZE 2048 + 128

#define MTU 9800
#ifdef FAKE_DPDK_MODE_XCHG_ASNI
#define RTE_MBUF_SIZE 9800 + 128
#else
#define RTE_MBUF_SIZE 2048 + 128
#endif

#define NUM_MBUFS 32767
#define NUM_HUGE_MBUFS 8191
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32
#define BURST_SIZE_XCHG 32
#define NUM_PORTS 1
#ifdef XCHG
#include "../../../utils/asq_descriptors.h"
#include "main.h"
#include <rte_xchg.h>
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
static inline int xchg_port_init(uint16_t port, struct rte_mempool *mbuf_pool,
                                 int nb_core) {
    const uint16_t rx_rings = nb_core;
    const uint16_t tx_rings = nb_core;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
#ifdef FAKE_DPDK_MODE_XCHG
    nb_rxd *= 8;
    nb_txd *= 8;
#endif
    int retval;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    static struct rte_eth_conf port_conf = {
        .rxmode =
            {
                .offloads = RTE_ETH_RX_OFFLOAD_SCATTER,
            },
        .txmode =
            {
                .mq_mode = RTE_ETH_MQ_TX_NONE,
                .offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS,
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

    /* Starting Ethernet port. 8< */
    retval = rte_eth_dev_start(port);
    /* >8 End of starting of ethernet port. */
    if (retval < 0) {
        printf("Error during getting device (port %u) info: %s\n", port,
               strerror(-retval));
        return retval;
    }
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
        printf("Freeing large packets\n");
        rte_mbuf_raw_free(metadata->mb);
        rte_free(metadata);
    }
}
#endif
/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

int option23(int argc, char **argv) {

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
struct xchg_state *xchg_init(int argc, char **argv) {
    printf("Running XCHG with descriptors of size %lu\n",
           sizeof(struct descriptor));
    struct xchg_state *state = malloc(sizeof(struct xchg_state));
    struct rte_mempool *mbuf_pool;
    uint16_t portid = 0;
    state->port = 0;
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
        return NULL;
    }
    argc -= ret;
    argv += ret;
    if (state == NULL) {
        printf("Error allocating memory for xchg_state\n");
        return NULL;
    }
    if (option23(argc, argv) != 0) {
        printf("Error parsing command line arguments\n");
        return NULL;
    }

#ifdef FAKE_DPDK_MODE_XCHG
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_HUGE_MBUFS * 8,
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_SIZE,
                                        rte_socket_id());
#else
    mbuf_pool =
        rte_pktmbuf_pool_create("MBUF_POOL", NUM_HUGE_MBUFS, MBUF_CACHE_SIZE, 0,
                                RTE_MBUF_SIZE, rte_socket_id());
#endif
    if (mbuf_pool == NULL) {
        printf("Error allocating mbuf pool\n");
        return NULL;
    }
    /* Initializing the desired port. */
    state->nb_core = 1;
    if (xchg_port_init(0, mbuf_pool, state->nb_core) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
    printf("\nRunning on %d cores\n", state->nb_core);
    return state;
}

void xchg_run(void *state, int (*app)(void *)) {
    rte_eal_mp_remote_launch(app, state, SKIP_MAIN);
    rte_eal_mp_wait_lcore();
    dgu_print_xstats();
    /* clean up the EAL */
    rte_eal_cleanup();
}

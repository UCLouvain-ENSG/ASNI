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
#include <sys/types.h>
#define debug(...)
#include "../../../utils/asq_descriptors.h"
// #define debug(...) printf(__VA_ARGS__)

#define HAVE_CYCLE 1

#define XCHG 1

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

struct rte_ether_addr macAddr1;
int nb_core = 1;
static int light = 0;
static int asq = 1;
struct rte_mempool *tx_mbuf_pool;
struct rte_mempool *mbuf_pool[2];
struct rte_mempool *mbuf_pool_small[2];
static volatile bool force_quit = false;
uint64_t nb_freed = 0;
uint64_t nb_refcnt1 = 0;
uint64_t nb_free_calls = 0;
uint64_t counter_total = 0;
uint64_t nb_sent = 0;
uint64_t tx_burst_tried = 0;
uint64_t tx_burst_failed = 0;
struct rte_mempool *ext_info_pool;
struct rte_mempool *metadata_pool;

int option(int argc, char **argv);

int src_port = -1;
int dst_port = -1;
/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int pure_dpdk_port_init(uint16_t port,
                                      struct rte_mempool *mbuf_pool) {
    const uint16_t rx_rings = 1;
    const uint16_t tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE * 16;
    int retval;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    static struct rte_eth_conf port_conf = {

        .rxmode =
            {
                .offloads = 0,
            },
        .txmode =
            {
                .mq_mode = RTE_ETH_MQ_TX_NONE,
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
    printf("nb_rxd : %d\n", nb_rxd);
    printf("nb_txd : %d\n", nb_txd);

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

    retval = rte_eth_dev_set_mtu(port, 9978);
    if (retval < 0) {
        printf("failed to set mtu\n");
        return retval;
    }
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

static inline void free_large_packet(struct metadata_tx_asni *metadata) {
    rte_pktmbuf_free(metadata->mb);
    rte_mempool_put(metadata_pool, metadata);
    rte_mempool_put(ext_info_pool, metadata->shinfo);
}

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
/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

/* Basic forwarding application lcore.*/

static inline void free_cb(void *addr, void *opaque) {
    struct metadata_tx_asni *md = (struct metadata_tx_asni *)opaque;
    free_large_packet(md);
}

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
    struct rte_mbuf *pkts_burst[BURST_SIZE];
    struct rte_mbuf *pkts_burst_tx[BURST_SIZE];
    struct rte_mbuf_ext_shared_info *ext_info;
    struct metadata_tx_asni *metadata;
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

            printf("RESULT-USEFULKCYCLES %lu\n", useful_cycles / 1000);
            if (counter_total > 0)
                printf("RESULT-CYCLES-PER-PACKET %lu\n",
                       useful_cycles / counter_total);
            if (useful_cycles + useless_cycles > 0)
                printf("RESULT-CPU-LOAD %f\n",
                       (double)useful_cycles /
                           (double)(useful_cycles + useless_cycles));
            printf("RESULT-NBFREE : %lu\n", nb_freed);
            printf("RESULT-REFCNT1 : %lu\n", nb_refcnt1);
            printf("RESULT-NBFREECALLS : %lu\n", nb_free_calls);
            return 0;
        }

#ifdef HAVE_CYCLE
        start_cycle = rte_get_tsc_cycles();
#endif
        /* Get burst of RX packets, from first port of pair. */
        const uint16_t nb_rx =
            rte_eth_rx_burst(src_port, 0, pkts_burst, BURST_SIZE_XCHG);
        if (nb_rx == 0) {
            continue;
        }
        for (int i = 0; i < nb_rx; i++) {
            uint32_t offset_desc = 16;
            uint8_t *data = rte_pktmbuf_mtod(pkts_burst[i], uint8_t *);
            uint8_t nb_desc = *data;
            payload =
                data + offset_desc + (nb_desc * sizeof(struct descriptor));
            if (unlikely(nb_desc < 1 || nb_desc > 64)) {
                printf(
                    "received packet with wrong number of descriptors : %d\n",
                    nb_desc);
            } else {
                if (rte_mempool_get(metadata_pool, (void **)&metadata) < 0) {
                    printf("failed to allocate metadata\n");
                    return -1;
                }
                if (rte_mempool_get(ext_info_pool, (void **)&ext_info) < 0) {
                    printf("failed to allocate ext_info\n");
                    return -1;
                }
                int nb_alloc_descriptors = rte_pktmbuf_alloc_bulk(
                    tx_mbuf_pool, pkts_burst_tx, nb_desc);
                if (nb_alloc_descriptors != 0) {
                    printf("failed to allocate tx_burst \n");
                    return -1;
                }
                metadata->mb = pkts_burst[i];
                ext_info->fcb_opaque = metadata;
                ext_info->free_cb = free_cb;
                ext_info->refcnt = nb_desc;
                metadata->shinfo = ext_info;

                struct descriptor *desc =
                    (struct descriptor *)(data + offset_desc);
                int length = desc->size;
                rte_pktmbuf_attach_extbuf(pkts_burst_tx[0], payload,
                                          (uintptr_t)payload, length, ext_info);
                pkts_burst_tx[0]->pkt_len = length;
                pkts_burst_tx[0]->data_len = length;
                nb_byte += desc->size;
                for (uint8_t j = 1; j < nb_desc; j++) {
                    counter_total++;
                    desc++;
                    length = desc->size;
                    nb_byte += length;
                    payload += length;
                    rte_pktmbuf_attach_extbuf(pkts_burst_tx[j], payload,
                                              rte_mem_virt2iova(payload),
                                              length, ext_info);
                    pkts_burst_tx[j]->pkt_len = length;
                    pkts_burst_tx[j]->data_len = length;
                }
                const uint16_t sent =
                    rte_eth_tx_burst(dst_port, qid, pkts_burst_tx, nb_desc);

                for (int i = sent; i < nb_desc; i++) {
                    rte_pktmbuf_free(pkts_burst_tx[i]);
                }
                tx_burst_tried += nb_desc;
                if (sent != nb_desc) {
                    tx_burst_failed += (nb_desc - sent);
                }
                nb_sent += sent;
            }
        }

#ifdef HAVE_CYCLE
        if (unlikely(start == 0)) {
            start = start_cycle;
        }
#endif
        debug("Received %d packets\n", nb_rx);

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
        if (pure_dpdk_port_init(portid, mbuf_pool[portid]) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", 0);

        if (rte_lcore_count() > 1)
            printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

        if (nb_core != 1)
            printf("Only supports one core.\n");
        printf("\nListening on port : %d.\n", port);
    }
    printf("Allocating huge pool : %d\n", RTE_HUGE_MBUF_SIZE);
    tx_mbuf_pool = rte_pktmbuf_pool_create("TX_MPOOL", NUM_HUGE_MBUFS * 16,
                                           MBUF_CACHE_SIZE, 0, RTE_MBUF_SIZE,
                                           rte_socket_id());
    if (tx_mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }
    ext_info_pool = rte_mempool_create("EXT_INFO_POOL", 8192,
                                       sizeof(struct rte_mbuf_ext_shared_info),
                                       0, 0, NULL, NULL, NULL, NULL, 0, 0);
    if (ext_info_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create ext_info_pool\n");
    }
    metadata_pool = rte_mempool_create("METADATA_POOL", 8192,
                                       sizeof(struct metadata_tx_asni), 0, 0,
                                       NULL, NULL, NULL, NULL, 0, 0);
    if (metadata_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create metadata_pool\n");
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

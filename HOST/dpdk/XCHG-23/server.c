/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include "../../../utils/MACaddress.h"
#include <getopt.h>
#include <inttypes.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>

#include "../../../utils/rdtsc.h"
#include "../../../utils/stats.h"



// #include <../../../utils/port_init.h>

/*Set to 0 or 1 if you want to debug or not*/
#define DEBUG 0

#define debug_printf(fmt, ...)                                                 \
    do {                                                                       \
        if (DEBUG)                                                             \
            fprintf(stdout, fmt, __VA_ARGS__);                                 \
    } while (0)

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define RTE_MBUF_SIZE 2048 + 128

#define MTU 9800
#define RTE_HUGE_MBUF_SIZE 32768

#define NUM_MBUFS 32767
#define NUM_HUGE_MBUFS 8191
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32
#define NUM_PORTS 1

#include <rte_xchg.h>

#include "main.h"

struct rte_ether_addr macAddr1;
int nb_core = 1;
int light = 0;
enum State { NO_ASQ, ASQ, HW_ASQ_DP, HW_ASQ_DD };

enum State server_version = NO_ASQ;

static volatile bool force_quit = false;

int option(int argc, char **argv);

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
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
                .offloads = 0,
            },
        .txmode =
            {
                .offloads = 0,
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

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    if (server_version == ASQ || server_version == HW_ASQ_DP ||
        server_version == HW_ASQ_DD) {
        retval = rte_eth_dev_set_mtu(port, MTU);
        if (retval != 0)
            return retval;
    }

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, NULL);
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
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (uint16_t q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }
    /* Starting Ethernet port. 8< */
    retval = rte_eth_dev_start(port);
    /* >8 End of starting of ethernet port. */
    if (retval < 0)
        return retval;

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
    if (signum == SIGINT || signum == SIGTERM || signum == SIGKILL || signum == SIGUSR1) {
        printf("\n\nSignal %d received, preparing to exit\n", signum);

        // Get port stats
        struct rte_eth_stats new_stats;
        rte_eth_stats_get(0, &new_stats);
        // Print stats
        printf("\nNumber of received packets : %ld"
               "\nNumber of missed packets : %ld"
               "\nNumber of queued RX packets : %ld"
               "\nNumber of dropped queued packet : %ld\n\n",
               new_stats.ipackets, new_stats.imissed, new_stats.q_ipackets[0],
               new_stats.q_errors[0]);

    if (signum != SIGUSR1)
        force_quit = true;
    }
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

/* Basic forwarding application lcore.*/
static int lcore_main(void *arg) {
    uint16_t port = (uintptr_t)arg;

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

    uint64_t counter = 0;
    uint64_t counter_total = 0;
#ifdef HAVE_MINIMAL
    // uint64_t timestamp = 0;
#endif
    uint64_t nb_byte = 0;
    struct descriptor *desc;

    struct my_xchg pkts_burst_store[BURST_SIZE] = {0};
    struct my_xchg *pkts_burst[BURST_SIZE];
    for (int i = 0; i < BURST_SIZE; i++) {
        pkts_burst[i] = &pkts_burst_store[i];
        pkts_burst[i]->buffer = 0;
    }

    uint32_t ip_dst = 0;
    uint32_t ip_src = 0;

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
 #if defined(HAVE_RTC) || defined(HAVE_NOCQE)
    unsigned guard = 0;
#endif
    struct rte_ipv4_hdr *ip_hdr;

    /* Main work of application loop. 8< */
    for (;;) {
        if (force_quit) {
            double time_elapsed = (double)(end - start) / rte_get_tsc_hz();
            print_stats();
            // printf("\nReceived %ld packets for a total of %ld packets in %f
            // seconds : throughput : %fGb/s\n"
            //        "rte_burst cycle : %ld, pkt_analysis cycle : %ld\n",
            //        counter, counter_total, time_elapsed, (nb_byte * 8 /
            //        time_elapsed) / 1000000000, rte_burst, pkt_analysis);

            // fprintf(fp, "%ld, %ld, %f, %f, %ld, %ld, %f, %f\n", counter,
            // counter_total, time_elapsed, (nb_byte * 8 / time_elapsed) /
            // 1000000000,
            //         rte_burst, pkt_analysis, counter / time_elapsed /
            //         1000000, counter_total / time_elapsed / 1000000);
            // fclose(fp);
            return 0;
        }

#ifdef HAVE_CYCLE
        start_cycle = rte_get_tsc_cycles();
#endif
        /* Get burst of RX packets, from first port of pair. */
        const uint16_t nb_rx =
            rte_eth_rx_burst_xchg(port, 0, pkts_burst, BURST_SIZE);

        if (unlikely(nb_rx == 0)) {
            //printf("No packets, sleeping for 100ms\n");
            //usleep(100000);
#ifdef HAVE_CYCLE
            end_cycle = rte_get_tsc_cycles();
            useless_cycles += (end_cycle - start_cycle - rdtsc_time);
#else
            if (counter_total > end_last + 32) {
                end = rte_get_tsc_cycles();
                end_last = counter_total;
            } else if (counter_total < 32) {
                start = rte_get_tsc_cycles();
            }
#endif
            continue;
        }

#ifdef HAVE_CYCLE
        if (unlikely(start == 0)) {
            start = start_cycle;
        }
#endif
        debug_printf("APP: Received %d packets\n", nb_rx);
        /* Do a small job on each descriptor on the ip field */
        for (unsigned index = 0; index < nb_rx; index++) {
            uint8_t *data;
            // Hacky solution to avoid handling packet not from the NIC

            data = pkts_burst[index]->buffer;

            debug_printf("APP: Data %p\n",data);
            if (light)
                rte_prefetch0(data);
            if (server_version == ASQ) {
                uint8_t nb_desc;
                uint32_t offset_desc;
                uint32_t offset_data;

                offset_desc = asq_header_size;
                nb_desc = *data;
               //     for (int i = 0; i < pkts_burst[index]->plen; i+=4)
                 //       printf("[%02x] %02x %02x %02x %02x\n", i, *(data + i), *(data + i + 1), *(data + i+2), *(data + i + 3));

                *data = 0;

                if (nb_desc < 1 || nb_desc > 32) {
                    printf("[%d] Invalid descriptor nb_desc is %d pktlen is len %d!\n", index, nb_desc,
                           pkts_burst[index]->plen);
                } else {
                    offset_data =
                        nb_desc * sizeof(struct descriptor) + offset_desc + 2;
                    debug_printf("APP: %d ASQ packets received in total len %d\n", nb_desc, pkts_burst[index]->plen);

                    for (unsigned i = 0; i < nb_desc; i++) {
                        desc = (struct descriptor *)(data + offset_desc);

                        /* if this is an IPv4 packet */
                        // printf("before if : %i\n");
                        if (light) {
                            ip_hdr = (struct rte_ipv4_hdr *)(data +
                                                             offset_data + 14);
                            ip_dst = rte_be_to_cpu_32(ip_hdr->dst_addr);
                            ip_src = rte_be_to_cpu_32(ip_hdr->src_addr);
                            (void)ip_src;
                            (void)ip_dst;
                        } else {
                            // printf("\nIP header doesn't match IPV4 type\n");
                        }
                        // printf("after if : %i\n");

                        //				ip_dst = desc->ip_dst;
                        //				ip_src = desc->ip_src;

                        offset_desc += sizeof(struct descriptor) + 2;
#if defined(HAVE_RTC)|| defined(HAVE_NOCQE) 
                        while (desc->data_len < 60 || desc->data_len > 1500) {
                            //debug_printf("[%u - %u] Pause on %p (desc %p) -> %d\n",
                            //      index, i, data, desc, desc->data_len);
                            rte_pause();
                            rte_mb();
                            guard++;
                            if (unlikely(guard > 1000000)) {
                                guard = 0;
                                printf("[%u/%u - %u/%u] ERROR : STUCK on %p "
                                       "(desc %p) -> %d. ASQ length is %d\n",
                                       index, nb_rx, i, nb_desc, data, desc,
                                       desc->data_len, pkts_burst[index]->plen);
                            for (int i = 0; i < 128; i++)
                                printf("%p : %d %x\n",data +i, *(data + i), *(data + i) );
                            }
                        }
#endif
                        offset_data += desc->data_len;
                        debug_printf("APP: [%u - %u] Len %d\n", index, i, desc->data_len);
                        nb_byte += desc->data_len;
#if defined(HAVE_RTC) || defined(HAVE_NOCQE)
                        desc->data_len = 0;
#endif
                        //				printf("timestamp : %ld,
                        //",
                        // desc->timestamp); timestamp++; printf("len : %d, ",
                        // desc->data_len);

                        //				printf("offset : %ld\n",
                        // offset);
                    }
                    counter_total += nb_desc;
                    counter++;
                    // rte_pktmbuf_free(bufs[index]);
                }    // end good asq desc
            } else { // not asq
                if (light) {
                    ip_hdr = (struct rte_ipv4_hdr *)(data + 14);
                    ip_dst = rte_be_to_cpu_32(ip_hdr->dst_addr);
    
                    ip_src = rte_be_to_cpu_32(ip_hdr->src_addr);
                    (void)ip_src;
                    (void)ip_dst;  
                
                }
                nb_byte += pkts_burst[index]->plen;
                // rte_pktmbuf_free(bufs[index]);
                counter_total++;
                counter++;
            }

            // printf("\nPort %u received %u packets for a total of %lu
            // packets\n", port, nb_rx, counter);
        } // rx_burst loop
          /* Free all received packets. */

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
            {"asq", no_argument, (int *)&server_version, ASQ},
            {"hw_asq_dp", no_argument, (int *)&server_version, HW_ASQ_DP},
            {"hw_asq_dd", no_argument, (int *)&server_version, HW_ASQ_DD},

        };
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "c:s:", long_options, &option_index);

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

        case 's':
            if (!isValidMacAddress(optarg)) {
                printf("source MAC address has wrong format. Expected format : "
                       "__:__:__:__:__:__\n");
                return -1;
            }
            s = 0;
            macAddr1.addr_bytes[0] = (int)strtol(optarg, NULL, 16);
            macAddr1.addr_bytes[1] = (int)strtol(optarg + 3, NULL, 16);
            macAddr1.addr_bytes[2] = (int)strtol(optarg + 6, NULL, 16);
            macAddr1.addr_bytes[3] = (int)strtol(optarg + 9, NULL, 16);
            macAddr1.addr_bytes[4] = (int)strtol(optarg + 12, NULL, 16);
            macAddr1.addr_bytes[5] = (int)strtol(optarg + 15, NULL, 16);
            break;

        case '?':
            /* getopt_long already printed an error message. */
            break;

        default:
            abort();
        }
    }

    // Check mandatory parameters:
    if (s == -1) {
        printf("-s : source MAC address is mandatory!\n");
        return -1;
    }

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
    if (server_version == ASQ || server_version == HW_ASQ_DP ||
        server_version == HW_ASQ_DD) {
        printf("Allocating huge pool\n");
        mbuf_pool = rte_pktmbuf_pool_create(
            "MBUF_POOL", NUM_HUGE_MBUFS, MBUF_CACHE_SIZE, 0, RTE_HUGE_MBUF_SIZE,
            rte_socket_id());
    } else {
        printf("Allocating small pool\n");
        mbuf_pool =
            rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                                    RTE_MBUF_SIZE, rte_socket_id());
    }
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initializing the desired port. */
    if (port_init(0, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);

    if (rte_lcore_count() > 1)
        printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

    if (nb_core != 1)
        printf("Only supports one core.\n");
    printf("\nListening on port : %d.\n", port);

    /* Handle the Control+C */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGUSR1, signal_handler);

    rte_eal_mp_remote_launch(lcore_main, (void *)(uintptr_t)port, SKIP_MAIN);

    rte_eal_mp_wait_lcore();

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

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

#include "../../../utils/rdtsc.h"
#include "../../../utils/stats.h"

//#include <../../../utils/port_init.h>

/*Set to 0 or 1 if you want to debug or not*/
#define DEBUG 0
#define PREV_DESC true

#define debug_printf(fmt, ...)                                                 \
    do {                                                                       \
        if (DEBUG)                                                             \
            fprintf(stderr, fmt, __VA_ARGS__);                                 \
    } while (0)

#define RX_RING_SIZE 1024
#define RTE_MBUF_SIZE 2048 + 128

#define MTU 9800
#define RTE_HUGE_MBUF_SIZE 32768

#define NUM_MBUFS 32767
#define NUM_HUGE_MBUFS 8191
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32
#define NUM_PORTS 1

struct rte_ether_addr macAddr1;
int nb_core = 1;
int light = 0;
enum State { NO_ASQ, ASQ, HW_ASQ_DP, HW_ASQ_DD };

enum State server_version = NO_ASQ;

static volatile bool force_quit = false;

#ifdef HAVE_MINIMAL
struct descriptor {
    uint16_t data_len;
    #if defined(FAKE_DPDK_DESC_PAD)
    uint8_t padding[FAKE_DPDK_DESC_PAD];
#endif
} __attribute__((packed));
#else
struct descriptor {
    uint32_t ip_src;
    uint32_t ip_dst;
    //uint64_t timestamp;
    uint32_t data_len;
    #if defined(FAKE_DPDK_DESC_PAD)
    uint8_t padding[FAKE_DPDK_DESC_PAD];
#endif
} __attribute__((packed));
#endif


struct custom_header {
    char padding1[2];
    uint32_t length;
    char padding2[2];
    uint32_t dst_ip;
    /* Plenty of space for other fields  */
    char padding3[38];
} __attribute__((packed));

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    const uint16_t rx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    int retval;
    struct rte_eth_dev_info dev_info;

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
    retval = rte_eth_dev_configure(port, rx_rings, 0, &port_conf);
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
    if (signum == SIGINT || signum == SIGTERM || signum == SIGKILL) {
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

        force_quit = true;
    }
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

/* Basic forwarding application lcore.*/
static int
lcore_main(void* arg) {
    uint16_t port = (uintptr_t) arg;

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
    printf("\nProcessing incoming packets on port : %d. [Ctrl+C to quit]\n", port);

    uint64_t counter = 0;
    uint64_t counter_total = 0;
#if !HAVE_MINIMAL
    uint64_t timestamp = 0;
#endif
    uint64_t nb_byte = 0;
    uint64_t index;
    struct descriptor *desc;
    struct rte_mbuf *bufs[BURST_SIZE];

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

    int i;

    struct rte_ipv4_hdr *ip_hdr;
    uint8_t nb_desc;
    uint8_t *data;
    uint32_t offset_desc;
    uint32_t offset_data;

    /* Main work of application loop. 8< */
    for (;;) {
        if (force_quit) {
            //DO NOT PUT end= here!
            printf("end : %ld\n", end);
            printf("start : %ld\n", start);
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
        const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

        if (unlikely(start == 0 && nb_rx > 0)) {
            start = rte_get_tsc_cycles();
        }
        if (unlikely(nb_rx == 0)) {

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
        /* Do a small job on each descriptor on the ip field */
        for (index = 0; index < nb_rx; index++) {
            // Hacky solution to avoid handling packet not from the NIC
            if (server_version != HW_ASQ_DP && server_version != HW_ASQ_DD) {
                data = rte_pktmbuf_mtod(bufs[index], uint8_t *);
            }
            if (light)
                rte_prefetch0(data);
            if (server_version == ASQ) {
                debug_printf("Inside ASQ\n", NULL);
                offset_desc = 16;
                nb_desc = *data;

                    if (nb_desc < 1 || nb_desc > 64) {
                        printf("[%d] Invalid descriptor %d %d!\n", index, nb_desc, 
                            bufs[index]->data_len);
                        rte_pktmbuf_free(bufs[index]);
                    } else {
                        offset_data = nb_desc * sizeof(struct descriptor) + offset_desc;

                        for (unsigned i = 0; i < nb_desc; i++) {
                            desc = (struct descriptor *)(data + offset_desc);

                            /* if this is an IPv4 packet */
                            // printf("before if : %i\n");
                            if (light) {
                                ip_hdr =
                                    (struct rte_ipv4_hdr *)(data + offset_data + 14);
                                ip_dst = rte_be_to_cpu_32(ip_hdr->dst_addr);
                                ip_src = rte_be_to_cpu_32(ip_hdr->src_addr);
                            } else {
                                // printf("\nIP header doesn't match IPV4 type\n");
                            }
                            // printf("after if : %i\n");

                            //				ip_dst = desc->ip_dst;
                            //				ip_src = desc->ip_src;

                            offset_desc += sizeof(struct descriptor) + 2;
                            offset_data += desc->data_len;
                            debug_printf("[%u - %u] Len %d\n",index,i, desc->data_len);
                            nb_byte += desc->data_len;

                            //				printf("timestamp : %ld, ", desc->timestamp);
                            //				timestamp++;
                            //				printf("len : %d, ", desc->data_len);

                        //				printf("offset : %ld\n",
                        // offset);
                    }
                    counter_total += nb_desc;
                    counter++;
                    rte_pktmbuf_free(bufs[index]);
                } // end good asq desc

            } else if (server_version == HW_ASQ_DP) {
                debug_printf("inside hw_asq_dp\n", NULL);
                uint32_t total_length = bufs[index]->pkt_len;
                debug_printf("Total length : %d\n", total_length);
                uint32_t curr_tot = 0;
                uint64_t dummy_counter;
                struct custom_header *ch;
                ch = (struct custom_header *)(rte_pktmbuf_mtod(bufs[index],
                                                               char *));
                while (curr_tot < total_length) {
                    counter++;
                    // printf("inside loop\n");
                    dummy_counter += ch->dst_ip;
                    int length = ch->length;
                    debug_printf("Packet length : %d\n", length);
                    nb_byte += length;
                    debug_printf("nb_byte : %ld\n", nb_byte);
                    curr_tot += length + sizeof(struct custom_header);
                    ch = (struct custom_header *)((char *)(ch + 1) + length);
                    counter_total++;
                }
                rte_pktmbuf_free(bufs[index]);
            } else if (server_version == HW_ASQ_DD) {
                debug_printf("inside hw_asq_dd\n", NULL);
                uint32_t total_length = bufs[index]->pkt_len;
                uint32_t curr_tot = 0;
                uint64_t dummy_counter;
                struct custom_header *ch;
                ch = (struct custom_header *)(rte_pktmbuf_mtod(bufs[index],
                                                               char *));
                while (curr_tot < total_length) {
                    counter++;
                    // printf("inside loop\n");
                    dummy_counter += ch->dst_ip;
                    int length = rte_cpu_to_be_32(ch->length);
                    debug_printf("Packet length : %d\n", length);
                    nb_byte += length;
                    curr_tot += length + sizeof(struct custom_header);
                    ch++;
                    debug_printf("nb_bytes : %ld\n", nb_byte);
                    counter_total++;
                }
                rte_pktmbuf_free(bufs[index]);
                debug_printf("Total length DD : %d\n", total_length);
            } else { // not asq
                debug_printf("inside not asq \n", NULL);
                if (light) {
                    ip_hdr = (struct rte_ipv4_hdr *)(data + 14);
                    ip_dst = rte_be_to_cpu_32(ip_hdr->dst_addr);
                    ip_src = rte_be_to_cpu_32(ip_hdr->src_addr);
                }
                nb_byte += bufs[index]->data_len;
                rte_pktmbuf_free(bufs[index]);
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
    printf("sizeof(struct descriptor) : %ld\n", sizeof(struct descriptor));
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
    // Print port MAC address
    struct rte_ether_addr addr;
    rte_eth_macaddr_get(0, &addr);
    printf("Port MAC address : %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
           addr.addr_bytes[0], addr.addr_bytes[1],
           addr.addr_bytes[2], addr.addr_bytes[3],
           addr.addr_bytes[4], addr.addr_bytes[5]);

    /* Handle the Control+C */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    rte_eal_mp_remote_launch(lcore_main, (void*)(uintptr_t)port, SKIP_MAIN);

    rte_eal_mp_wait_lcore();

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}

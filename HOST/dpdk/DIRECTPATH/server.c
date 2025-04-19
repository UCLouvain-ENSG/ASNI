/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <getopt.h>

#include "mlx5/mlx5.h"


//#include <../../../utils/port_init.h>

#define RX_RING_SIZE 1024
#define RTE_MBUF_SIZE 2048 + 128

#define MTU 9800
#define RTE_HUGE_MBUF_SIZE 32768

#define NUM_MBUFS 32767
#define NUM_HUGE_MBUFS 8191
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32
#define NUM_PORTS 1


int nb_core = 1;
static int light = 0;
static int asq = 0;

static volatile bool force_quit = false;


/* Basic forwarding application lcore.*/
static int
lcore_main(uint16_t port) {

    printf("\nProcessing incoming packets on port : %d. [Ctrl+C to quit]\n", port);

    uint64_t counter = 0;
    uint64_t counter_total = 0;
    uint64_t timestamp = 0;
    uint64_t nb_byte = 0;
    uint64_t index;
    struct descriptor *desc;
    struct my_bufs *bufs[BURST_SIZE];

    uint32_t ip_dst = 0;
    uint32_t ip_src = 0;

    uint64_t start = 0;
    uint64_t end = 0;
#if HAVE_CYCLE
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
            double time_elapsed = (double)(end - start) / rte_get_tsc_hz();
            printf("RESULT-TESTTIME %f\n", time_elapsed);
            printf("RESULT-THROUGHPUT %fGbps\n", (((nb_byte +24*counter_total) * 8) / time_elapsed) / 1000000000);
            printf("RESULT-COUNT %ld\n", counter_total);
            printf("RESULT-PPS %f\n", (double)counter_total / (time_elapsed));
            printf("RESULT-GOODPUT %fGbps\n", ((nb_byte * 8) / time_elapsed) / 1000000000);
            printf("RESULT-USEFULKCYCLES %lu\n", useful_cycles / 1000);
            if (counter_total > 0)
                printf("RESULT-CYCLES-PER-PACKET %d\n", useful_cycles / counter_total);
            if (useful_cycles + useless_cycles  > 0)
                printf("RESULT-CPU-LOAD %f\n", (double)useful_cycles / (double)(useful_cycles + useless_cycles));
            // printf("\nReceived %ld packets for a total of %ld packets in %f seconds : throughput : %fGb/s\n"
            //        "rte_burst cycle : %ld, pkt_analysis cycle : %ld\n",
            //        counter, counter_total, time_elapsed, (nb_byte * 8 / time_elapsed) / 1000000000, rte_burst, pkt_analysis);

            // fprintf(fp, "%ld, %ld, %f, %f, %ld, %ld, %f, %f\n", counter, counter_total, time_elapsed, (nb_byte * 8 / time_elapsed) / 1000000000,
            //         rte_burst, pkt_analysis, counter / time_elapsed / 1000000, counter_total / time_elapsed / 1000000);
            // fclose(fp);
            return 0;
        }

#if HAVE_CYCLE
        start_cycle = rte_get_tsc_cycles();
#endif
        /* Get burst of RX packets, from first port of pair. */
        //TODO const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);


        if (unlikely(nb_rx == 0)) {

#if HAVE_CYCLE
            end_cycle = rte_get_tsc_cycles();
            useless_cycles += (end_cycle - start_cycle);
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

#if HAVE_CYCLE
        if (start == 0) {
            start = start_cycle;
        }
#endif
        /* Do a small job on each descriptor on the ip field */
        for (index = 0; index < nb_rx; index++) {
            //Hacky solution to avoid handling packet not from the NIC

                //data = rte_pktmbuf_mtod(bufs[index], uint8_t *);
                data = 0;
                if (light)
                    rte_prefetch0(data);
                if (asq) {
                    offset_desc = 16;
                    nb_desc = *data;
                    if (nb_desc < 1 || nb_desc > 32) {
                        printf("Invalid descriptor %d %d!\n", nb_desc, bufs[index]->data_len);
                        //TODO rte_pktmbuf_free(bufs[index]);
                    } else {
                        offset_data = nb_desc * sizeof(struct descriptor) + offset_desc;

                        printf("%d packets received\n", *nb_desc);

                        for (i = 0; i < nb_desc; i++) {
                            desc = (struct descriptor *)(data + offset_desc);

                            /* if this is an IPv4 packet */
                            //printf("before if : %i\n");
                            if (light) {
                                ip_hdr = (struct rte_ipv4_hdr *)(data + offset_data);
                                ip_dst = rte_be_to_cpu_32(ip_hdr->dst_addr);
                                ip_src = rte_be_to_cpu_32(ip_hdr->src_addr);
                            } else {
                                //printf("\nIP header doesn't match IPV4 type\n");
                            }
                            //printf("after if : %i\n");

                            //				ip_dst = desc->ip_dst;
                            //				ip_src = desc->ip_src;

                            offset_desc += sizeof(struct descriptor);
                            offset_data += desc->data_len;

                            nb_byte += desc->data_len;

                            //				printf("timestamp : %ld, ", desc->timestamp);
                            //				timestamp++;
                            //				printf("len : %d, ", desc->data_len);

                            //				printf("offset : %ld\n", offset);
                        }
                        counter_total += nb_desc;
                        counter++;
                        rte_pktmbuf_free(bufs[index]);
                    } //end good asq desc


                } else { // not asq
                    if (light) {
                                ip_hdr = (struct rte_ipv4_hdr *)(data + offset_data);
                                ip_dst = rte_be_to_cpu_32(ip_hdr->dst_addr);
                                ip_src = rte_be_to_cpu_32(ip_hdr->src_addr);
                    }
                    nb_byte += bufs[index]->data_len;
                    rte_pktmbuf_free(bufs[index]);
                    counter_total++;
                    counter++;
                }

            // printf("\nPort %u received %u packets for a total of %lu packets\n", port, nb_rx, counter);
        } //rx_burst loop
                            /* Free all received packets. */

#if HAVE_CYCLE
        end_cycle = rte_get_tsc_cycles();
        useful_cycles += (end_cycle - start_cycle);


        end = end_cycle;
#endif

    }
}


int option(int argc, char **argv) {

    int c;
    int s = -1;

    while (1) {
        static struct option long_options[] =
            {
                /* These options set a flag. */
                {"light", no_argument, &light, 1},
                {"asq", no_argument, &asq, 1},

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
                printf("source MAC address has wrong format. Expected format : __:__:__:__:__:__\n");
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
    uint16_t portid = 0;
    uint16_t port = 0;

    /* Initialize the MAC addresses to count the incoming number of packets */
    ret = option(argc, argv);
    if (ret == -1)
            return -1;

    /* Handle the Control+C */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);


    directpath_init();


    return 0;
}

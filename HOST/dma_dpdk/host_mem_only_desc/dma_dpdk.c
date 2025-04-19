/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <getopt.h>
#include <inttypes.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utils.h>

/*doca imports*/
#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>

#include "consts.h"
#include "descriptors_definition.h"
#include "dma_common.h"
#include "dma_exchange.h"
#include "dma_jobs.h"
#include "doca_utils.h"
#include "udp_comm.h"
#include <rte_atomic.h>
#include <rte_compat.h>
#include <rte_cycles.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_tcp.h>

#include <signal.h>

#define max_nb_core 7
#define RTE_MBUF_HUGE_SIZE 30000
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define RX_RING_SIZE 1024

DOCA_LOG_REGISTER(MAIN);

#define DESCRIPTOR_NB 2048 /* The number of descriptor in the ring (MAX uint16_t max val or change head-tail to uint16_t) */

uint64_t start = 0;
uint64_t nb_bytes = 0;
char PCIE_ADDR[128] = {0};
char dummy[PAYLOAD_ARRAY_SIZE];
uint32_t nb_core = 7; /* The number of Core working on the NIC (max 7) */
static volatile bool force_quit = false;

static void
signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit\n", signum);
        force_quit = true;
    }
}

doca_error_t
stable_dma_dpdk_run(struct doca_pci_bdf *pcie_addr) {
    // DOCA
    printf("Application started\n");
    struct program_core_objects state[max_nb_core];
    doca_error_t result;
    char *export_desc;
    int core = 0;
    uint64_t counter[max_nb_core];
    uint64_t pos[max_nb_core];
    uint64_t timestamp[max_nb_core];
    int ret = 0;
    char *src_buffers_desc[max_nb_core];
    size_t src_buffers_size_desc[max_nb_core];

    char *src_buffers_payloads[max_nb_core];
    size_t src_buffers_size_payloads[max_nb_core];
    int index;
    int udp_port = 0;
    printf("nb_core : %d\n");
    //const struct rte_memzone* tst = rte_memzone_reserve("test",100,rte_socket_id(),0);
    // if(tst == NULL){
    //     printf("reserve failed\n");
    // }
    // printf("addr : %p\n",(uint64_t)tst->addr_64);
    // printf("iova : %p\n",(uint64_t)tst->iova);
    // struct rte_eth_dev_info dev_info;
    // result = rte_eth_dev_info_get(0, &dev_info);
    // if (result != 0)
    //     rte_exit(EXIT_FAILURE,
    //              "Error during getting device (port %u) info: %s\n",
    //              0, strerror(result));

    // struct mlx5_common_device *mlx5_dev = to_mlx5_device(dev_info.device);
    // if (!mlx5_dev) {
    //     printf("to_mlx5_device failed\n");
    //     return -1;
    // } else {
    //     printf("function return successfull\n");
    // }
    rte_iova_t iova;
    // struct mlx5_pmd_mr pmd_mr;
    for (index = 0; index < nb_core; index++) {
        printf("inside loop\n");
        // Init the variable
        counter[index] = 0;
        pos[index] = 0;
        timestamp[index] = 0;
        src_buffers_size_desc[index] = sizeof(struct descriptor) * DESCRIPTOR_NB;
        src_buffers_desc[index] = (char *)rte_zmalloc(NULL, src_buffers_size_desc[index], 0x1000);
        if (src_buffers_desc[index] == NULL) {
            printf("failed to malloc\n");
        }
        //temporary
        src_buffers_size_payloads[index] = PAYLOAD_ARRAY_SIZE;
        //struct rte_memzone *tst = rte_memzone_reserve("test", src_buffers_size_payloads[index], rte_socket_id(), 0);
        src_buffers_payloads[index] = (char *)rte_zmalloc(NULL, src_buffers_size_payloads[index], 0x1000);
        if (src_buffers_payloads[index] == NULL) {
            printf("failed to malloc\n");
        }
        result = dma_export_memory(pcie_addr,
                                   src_buffers_desc[index],
                                   src_buffers_size_desc[index],
                                   udp_port++);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to create DMA engine: %s", doca_error_get_descr(result));
            return result;
        }
        usleep(100000);

        // char *test = rte_malloc(NULL, src_buffers_size_payloads[index], 0);
        // if (test == NULL) {
        //     printf("failed to allocate test\n");
        // }
        // size_t length = src_buffers_size_payloads[index];

        // ret = mlx5_common_verbs_reg_mr(mlx5_dev->pd, src_buffers_payloads[index], src_buffers_size_payloads[index], &pmd_mr);
        // if (ret < 0) {
        //     printf("reg_mr failed\n");
        //     return -1;
        // } else {
        //     printf("reg_mr_succeded\n");
        // }
        // iova = rte_mem_virt2iova(pmd_mr.addr);
        // if (iova != RTE_BAD_IOVA) {
        //     printf("rte_mem_virt2iova succeeded\n");
        // } else {
        //     printf("rte_mem_virt2iova failed\n");
        //     return -1;
        // }

        // ret = send_udp_data(&pmd_mr, sizeof(struct mlx5_pmd_mr), udp_port++);
        // if (ret < 0) {
        //     printf("failed to send data\n");
        // } else {
        //     printf("data_sent : %d\n", ret);
        // }
        // usleep(100000);
        // ret = send_udp_data(&iova, sizeof(rte_iova_t), udp_port++);
        // if (ret < 0) {
        //     printf("failed to send data\n");
        // } else {
        //     printf("data_sent : %d\n", ret);
        // }

        /* DOCA : Open the relevant DOCA device */
        result = dma_export_memory(pcie_addr,
                                   src_buffers_payloads[index],
                                   src_buffers_size_payloads[index],
                                   udp_port++);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to create DMA engine: %s", doca_error_get_descr(result));
            return result;
        }
        usleep(100000);
    }
    struct descriptor **descriptors = (struct descriptor **)src_buffers_desc;
    char **payloads = src_buffers_payloads;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Read the buffer */
    // int *ptr = (int *)src_buffers_payloads[0];
    // for(int i = 0; i < PAYLOAD_ARRAY_SIZE/sizeof(int);i++){
    //     printf("ptr_val : %d\n",ptr[i]);
    // }
    memset(src_buffers_payloads[0], 0, src_buffers_size_payloads[0]);
    printf("buffer start ptr : %p\n", src_buffers_payloads[0]);
    // while (!force_quit) {
    //     for (int i = 0; i < 2048; i++) {
    //         printf("c : %c\n", *(src_buffers_payloads[0] + i));
    //         usleep(1000);
    //     }
    // }

    // while (!force_quit) {
    //     for (int i = 0; i < 2048; i++) {
    //         printf("==================start seg nb : %d====================\n", i);
    //         printf("strcmp :%d\n", memcmp(dummy, src_buffers_payloads[0] + i * 2048, PAYLOAD_ARRAY_SIZE));
    //         struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)src_buffers_payloads[0] + i * 2048;
    //         printf("type : %x\n", htons(eth_hdr->ether_type));
    //         struct rte_ipv4_hdr *ip_hdr = eth_hdr + 1;
    //         printf("len : %zu\n", htons(ip_hdr->total_length));
    //         struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((unsigned char *)ip_hdr +
    //                                                          sizeof(struct rte_ipv4_hdr));
    //         unsigned char *payload = (unsigned char *)(tcp + 1);
    //         printf("payload : %s\n", payload);
    //         printf("==================end seg nb : %d====================\n", i);
    //     }
    // }
    // printf("strcmp :%d\n", memcmp(dummy, src_buffers_payloads[0], PAYLOAD_ARRAY_SIZE));
    for (;;) {
        for (core = 0; core < nb_core; core++) {
            //printf("nb_core : %d\n", core);
            if (force_quit) {
                uint64_t end = rte_get_tsc_cycles();
                double time_elapsed = (double)(end - start) / rte_get_tsc_hz();
                printf("RESULT-THROUGHPUT %fGbps\n", ((nb_bytes * 8) / time_elapsed) / 1000000000);
                // for (int i = 0; i < DESCRIPTOR_NB; i++) {
                //     printf("descriptor[%d] timestamp : %ld full : %d\n", i, descriptors[core][i].timestamp, descriptors[core][i].full);
                // }
                // printf("local timstamp : %ld\n", timestamp[core]);
                // printf("descriptor : %lu pos : %ld, full : %d\n", descriptors[core][pos[core]].timestamp, pos[core], descriptors[core][pos[core]].full);
                // printf("descriptor+1 : %lu pos : %ld, full : %d\n", descriptors[core][pos[core] + 1].timestamp, pos[core] + 1, descriptors[core][pos[core] + 1].full);
                return 0;
            }
            int rx_counter = 0;
            while (!force_quit) {
                for (int i = 0; i < 32; i++) {
                    printf("==================start seg nb : %d====================\n", i);
                    printf("strcmp :%d\n", memcmp(dummy, src_buffers_payloads[0] + (i * (2048 + 128)), PAYLOAD_ARRAY_SIZE));
                    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)(src_buffers_payloads[0] + 128 + (i * (2048+128)));
                    printf("type : %x\n", htons(eth_hdr->ether_type));
                    struct rte_ipv4_hdr *ip_hdr = eth_hdr + 1;
                    printf("len : %zu\n", htons(ip_hdr->total_length));
                    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((unsigned char *)ip_hdr +
                                                                     sizeof(struct rte_ipv4_hdr));
                    unsigned char *payload = (unsigned char *)(tcp + 1);
                    printf("payload : %s\n", payload);
                    printf("==================end seg nb : %d====================\n", i);
                }
            }
            return 0;
            while (descriptors[core][pos[core]].full && rx_counter < 32) {
                printf("strcmp :%d\n", memcmp(dummy, src_buffers_payloads[0], PAYLOAD_ARRAY_SIZE));

                //printf("before tsc_cycles\n");
                if (start == 0) {
                    start = rte_get_tsc_cycles();
                }
                uint16_t src_port;
                uint16_t dst_port;
                uint32_t src_addr;
                uint32_t dst_addr;
                printf("payload_ptr : %p\n", descriptors[core][pos[core]].payload_ptr);
                // printf("buffer start ptr : %p\n", src_buffers_payloads[index]);
                // printf("memcmp2 : %d\n", memcmp(descriptors[core][pos[core]].payload_ptr + 128, dummy, descriptors[core][pos[core]].size));
                struct rte_ether_hdr *eth_hdr = descriptors[core][pos[core]].payload_ptr + 128;
                printf("val : %d\n", *(int *)(descriptors[core][pos[core]].payload_ptr + 128));
                // printf("type : %d\n", RTE_ETHER_TYPE_IPV4);
                // printf("type2 : %d\n", eth_hdr->ether_type);
                if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                    // printf("inside ether\n");
                    struct rte_ipv4_hdr *ip_hdr;
                    struct rte_tcp_hdr *tcp_hdr;
                    ip_hdr = (struct rte_ipv4_hdr *)(struct rte_ether_hdr *)(eth_hdr + sizeof(struct rte_ether_hdr));
                    if (ip_hdr->next_proto_id == IPPROTO_TCP) {
                        tcp_hdr = (struct rte_tcp_hdr *)((unsigned char *)ip_hdr +
                                                         sizeof(struct rte_ipv4_hdr));
                        src_addr = ip_hdr->src_addr;
                        dst_addr = ip_hdr->dst_addr;
                        src_port = tcp_hdr->src_port;
                        dst_port = tcp_hdr->dst_port;
                    }
                } else {
                    printf("payload is not ipv4\n");
                }

                //printf("after tsc_cycles\n");
                // counter[core]++;
                // timestamp[core]++;
                nb_bytes += descriptors[core][pos[core]].size;
                //printf("nb_bytes : %ld\n", nb_bytes);
                // if (descriptors[core][pos[core]].timestamp != timestamp[core]) {
                //     printf("Core %d : wrong timestamp, expected : %lu, received : %lu\n",
                //            core + 1, timestamp[core], descriptors[core][pos[core]].timestamp);
                //     return 1;
                // }

                descriptors[core][pos[core]].full = 0;
                pos[core]++;
                if (pos[core] == DESCRIPTOR_NB)
                    pos[core] = 0;
                rx_counter++;
            }
        }
    }

    /* DOCA : Destroy all relevant DOCA core objects */
    for (index = 0; index < nb_core; index++)
        host_destroy_core_objects(&state[index]);

    /* DOCA : Free API pre-allocated exported string */
    free(export_desc);

    return result;
}

static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    const uint16_t rx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    static struct rte_eth_conf port_conf = {0};

    //	static struct rte_eth_conf port_conf;
    //        memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n",
               port, strerror(-retval));
        return retval;
    }

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, 0, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, NULL);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                        rte_eth_dev_socket_id(port), NULL, mbuf_pool);
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

/*
 * Sample main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int main(int argc, char **argv) {
    // DOCA
    int res = 0;
    struct doca_pci_bdf pcie_dev;
    doca_error_t result;
    struct doca_logger_backend *stdout_logger = NULL;
    struct rte_mempool *mbuf_pool;
    /* Create a logger backend that prints to the standard output */
    result = doca_log_create_file_backend(stdout, &stdout_logger);
    if (result != DOCA_SUCCESS)
        return EXIT_FAILURE;

    //init EAL, necessary for rte_cycles
    res = rte_eal_init(argc, argv);
    if (res < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    argc -= res;
    argv += res;

    int c;
    while ((c = getopt(argc, argv, "c:p:")) != -1)
        switch (c) {
        case 'p':
            strcpy(PCIE_ADDR, optarg);
            break;
        case 'c':
            nb_core = atoi(optarg);
            printf("Using %d cores\n", nb_core);
            break;
        case '?':
            if (optopt == 'c')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint(optopt))
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf(stderr,
                        "Unknown option character `\\x%x'.\n",
                        optopt);
            return 1;
        default:
            abort();
        }
    if (PCIE_ADDR == NULL) {
        fprintf(stderr, "You should specify the pcie_addr with the -p option\n");
    }
    result = doca_pci_bdf_from_string(PCIE_ADDR, &pcie_dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to parse pci address: %s", doca_error_get_descr(result));
        printf("PCIE_ADDR : %s\n", PCIE_ADDR);
        return EXIT_FAILURE;
    }

    // struct doca_devinfo **dev_list;
    // uint32_t nb_devs;
    // struct doca_pci_bdf buf = {};
    // int res;
    // size_t i;

    // /* Set default return value */
    // struct doca_dev **retval = NULL;

    // res = doca_devinfo_create_list(&dev_list, &nb_devs);
    // if (res != DOCA_SUCCESS) {
    //     DOCA_LOG_ERR("Failed to load doca devices list. Doca_error value: %d", res);
    //     return res;
    // }
    // printf("nb_devs : %d\n", nb_devs);
    // /* Search */
    // printf("hello1\n");
    // for (i = 0; i < nb_devs; i++) {
    //     printf("hello\n");
    //     res = doca_devinfo_get_pci_addr(dev_list[i], &buf);
    //     if (res == DOCA_SUCCESS) {
    //         printf("inside success\n");
    //         /* If any special capabilities are needed */
    //         if (dma_jobs_is_supported != NULL && dma_jobs_is_supported(dev_list[i]) != DOCA_SUCCESS) {
    //             printf("failed\n");
    //             continue;
    //         }

    //         printf("success\n");
    //         /* if device can be opened */
    //         res = doca_dev_open(dev_list[i], retval);
    //         if (res == DOCA_SUCCESS) {
    //             doca_devinfo_list_destroy(dev_list);
    //             return res;
    //         }
    //     }
    // }
    // int test = rte_pmd_mlx5_sync_flow(2, 3);
    // mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
    //                                     MBUF_CACHE_SIZE, 0, RTE_MBUF_HUGE_SIZE, rte_socket_id());
    // if (mbuf_pool == NULL)
    //     rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    // /* Initializing the desired port. */
    // if (port_init(0, mbuf_pool) != 0)
    //     rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", 0);
    result = stable_dma_dpdk_run(&pcie_dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("DMA function has failed: %s", doca_error_get_descr(result));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

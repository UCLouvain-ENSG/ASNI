/*
 * Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#include <doca_argp.h>
#include <doca_flow.h>
#include <doca_log.h>
#include <dpdk_utils_simple.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>

#include "consts.h"
#include "dpdk_utils.h"
#include "dpdk_utils2.h"
#include "dpdk_utils_asni.h"
#include "my_structs.h"
#include "processing.h"
#include "structs_enums.h"
#define MAX_NB_CORES 12
#define MAX_SEGS_BUFFER_SPLIT 8
#define DEFAULT_MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#define MBUF_POOL_NAME_PFX "mb_pool"

int IN_PORT = 0;
int OUT_PORT = 3;

int NB_CORES = 12;

struct my_stats mstats[32];

// uint32_t mbuf_data_size_n = 1;
// uint16_t mbuf_data_size[MAX_SEGS_BUFFER_SPLIT] = {
// 	DEFAULT_MBUF_DATA_SIZE
// };

enum SG_TYPE sg_type;
bool reverse = false;
struct rte_mempool *doca_mempool;
struct rte_mempool *mbuf_pool;
uint16_t rx_pkt_seg_lengths[MAX_SEGS_BUFFER_SPLIT];
uint8_t rx_pkt_nb_segs; /**< Number of segments to split */
uint16_t rx_pkt_seg_offsets[MAX_SEGS_BUFFER_SPLIT];
uint8_t rx_pkt_nb_offs; /**< Number of specified offsets */

DOCA_LOG_REGISTER(FLOW_DESC_CREATION::MAIN);

static volatile bool force_quit = false;
/* Sample's Logic */
doca_error_t flow_vxlan_encap(int nb_queues, volatile bool *fq, int NB_CORES,
                              int starting_port_id);

static doca_error_t core_callback(void *param, void *config) {
    NB_CORES = *(int *)param;
    printf("Running with %d cores\n", NB_CORES);
    return DOCA_SUCCESS;
}

static doca_error_t sg_type_callback(void *param, void *config) {
    sg_type = *(int *)param;
    printf("using SG_TYPE %d\n", sg_type);
    return DOCA_SUCCESS;
}

static doca_error_t reverse_callback(void *param, void *config) {
    reverse = *(bool *)param;
    printf("Reversing ports :%d\n", reverse);
    return DOCA_SUCCESS;
}

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM || signum == SIGKILL) {
        printf("\n\nSignal %d received, preparing to exit\n", signum);

        // Get port stats
        struct rte_eth_stats stats = {0};
        rte_eth_stats_get(IN_PORT, &stats);
        // Print stats
        printf("=====================\n");
        printf("PORT %d : \n", IN_PORT);
        printf("\nNumber of received packets : %ld"
               "\nNumber of missed packets : %ld"
               "\nNumber of erroneous received packets : %ld"
               "\nNumber of packets transmitted : %ld"
               "\nNumber of tx errors : %ld\n\n",
               stats.ipackets, stats.imissed, stats.ierrors, stats.opackets,
               stats.oerrors);

        printf("RESULT-NIC-DROPPED-ARM %lu\n", stats.imissed);
        printf("RESULT-NIC-RECEIVED-ARM %lu\n", stats.ipackets);
        printf("RESULT-RATIO-DROPPED-ARM %f\n",
               (double)stats.imissed / (double)stats.ipackets);
        for (int i = 0; i < NB_CORES; i++) {
            printf("q_ipackets[%d] : %ld\n", i, stats.q_ipackets[i]);
        }
        force_quit = true;
        rte_eth_stats_get(OUT_PORT, &stats);
        printf("=====================\n");
        printf("PORT %d : \n", OUT_PORT);
        printf("\nnumber of received packets : %ld"
               "\nnumber off missed packets : %ld"
               "\nnumber of erroneous received packets : %ld"
               "\nnumber of packets transmitted : %ld"
               "\nnumber of tx errors : %ld\n\n",
               stats.ipackets, stats.imissed, stats.ierrors, stats.opackets,
               stats.oerrors);
        printf("RESULT-NIC-PKT-SENT %lu\n", stats.opackets);
        printf("RESULT-NIC-PKT-TX-ERROR %lu\n", stats.oerrors);

        uint64_t sum = 0;
        for (int i = 0; i < NB_CORES; i++) {
            sum += mstats[i].nb_packets_send;
        }
        printf("nb_packets_send  : %ld\n", sum);
        force_quit = true;
    }
}

static int job(void *arg) {
    int id = rte_lcore_id() - 1;
    scatter_gather_packets(IN_PORT, OUT_PORT, id, &force_quit, doca_mempool,
                           sg_type, &mstats[id]);
    return 0;
}

int main(int argc, char **argv) {

    doca_error_t result;
    int exit_status = EXIT_SUCCESS;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Create a logger backend that prints to the standard output */
    result = doca_log_backend_create_standard();
    if (result != DOCA_SUCCESS)
        return EXIT_FAILURE;

    result = doca_argp_init("doca_flow_drop", NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init ARGP resources: %s",
                     doca_error_get_descr(result));
        return EXIT_FAILURE;
    }

    struct doca_argp_param *core_param;
    result = doca_argp_param_create(&core_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create ARGP param: %s",
                     doca_error_get_descr(result));
        return result;
    }

    doca_argp_param_set_short_name(core_param, "c");
    doca_argp_param_set_long_name(core_param, "cores");
    doca_argp_param_set_description(core_param, "Number of cores to use");
    doca_argp_param_set_callback(core_param, core_callback);
    doca_argp_param_set_type(core_param, DOCA_ARGP_TYPE_INT);
    doca_argp_param_set_mandatory(core_param);

    result = doca_argp_register_param(core_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register program param: %s",
                     doca_error_get_descr(result));
        return result;
    }

    struct doca_argp_param *sg_type_param;
    result = doca_argp_param_create(&sg_type_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create ARGP param: %s",
                     doca_error_get_descr(result));
        return result;
    }

    doca_argp_param_set_short_name(sg_type_param, "t");
    doca_argp_param_set_long_name(sg_type_param, "type");
    doca_argp_param_set_description(sg_type_param, "packet organisation");
    doca_argp_param_set_callback(sg_type_param, sg_type_callback);
    doca_argp_param_set_type(sg_type_param, DOCA_ARGP_TYPE_INT);
    doca_argp_param_set_mandatory(sg_type_param);

    result = doca_argp_register_param(sg_type_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register program param: %s",
                     doca_error_get_descr(result));
        return result;
    }

    struct doca_argp_param *reverse_param;
    result = doca_argp_param_create(&reverse_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create ARGP param: %s",
                     doca_error_get_descr(result));
        return result;
    }

    doca_argp_param_set_short_name(reverse_param, "r");
    doca_argp_param_set_long_name(reverse_param, "reverse");
    doca_argp_param_set_description(reverse_param, "reverse port order");
    doca_argp_param_set_callback(reverse_param, reverse_callback);
    doca_argp_param_set_type(reverse_param, DOCA_ARGP_TYPE_INT);
    doca_argp_param_set_mandatory(reverse_param);

    result = doca_argp_register_param(reverse_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register program param: %s",
                     doca_error_get_descr(result));
        return result;
    }

    doca_argp_set_dpdk_program(dpdk_init);
    result = doca_argp_start(argc, argv);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to parse sample input: %s",
                     doca_error_get_descr(result));
        doca_argp_destroy();
        return EXIT_FAILURE;
    }

    int retval;
    for (int i = 0; i < rte_eth_dev_count_avail(); i++) {
        struct rte_ether_addr addr;
        retval = rte_eth_macaddr_get(i, &addr);
        if (retval != 0)
            return retval;
        printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
               " %02" PRIx8 " %02" PRIx8 "\n",
               (unsigned int)i, addr.addr_bytes[0], addr.addr_bytes[1],
               addr.addr_bytes[2], addr.addr_bytes[3], addr.addr_bytes[4],
               addr.addr_bytes[5]);
    }
    printf("nb_core : %d\n", NB_CORES);
    int starting_port = 0;
    int portid = 3;
    if (reverse) {
        printf("Reversing the two ports : true\n");
        IN_PORT = 2;
        OUT_PORT = 1;
        starting_port = IN_PORT;
        portid = OUT_PORT;
    }

    struct application_dpdk_config dpdk_config = {
        .port_config.nb_ports = 1,
        .port_config.nb_queues = NB_CORES,
        .port_config.nb_hairpin_q = 0,
        .sft_config = {0},
        .reserve_main_thread = true,
    };

    /* update queues and ports */
    if (sg_type == DD) {
        result =
            dpdk_queues_and_ports_init_split(&dpdk_config, true, starting_port);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to update ports and queues");
            dpdk_fini();
            doca_argp_destroy();
            return EXIT_FAILURE;
        }
    } else if (sg_type == DP) {
        result = dpdk_queues_and_ports_init_split(&dpdk_config, false,
                                                  starting_port);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to update ports and queues");
            dpdk_fini();
            doca_argp_destroy();
            return EXIT_FAILURE;
        }
    }
    doca_mempool = dpdk_config.mbuf_pool;
    /*Init port not used in doca flow*/

    mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL_HUGE", NUM_MBUFS * NB_CORES, MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initializing the desired port. */

    printf("Init port %d using DPDK\n", portid);
    if (large_mtu_port_init(portid, mbuf_pool, MAX_NB_CORES, MAX_NB_CORES, 9800,
                            128) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);

    /* run sample */
    result = flow_vxlan_encap(dpdk_config.port_config.nb_queues, &force_quit,
                              NB_CORES, starting_port);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("flow_vxlan_encap() encountered errors");
        rte_exit(EXIT_FAILURE, "Pipe initialization failed\n");
    }

    int lcore_id;
    int counter = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (counter == NB_CORES) {
            break;
        }
        rte_eal_remote_launch(job, NULL, lcore_id);
        counter++;
    }
    printf("EVENT nic_ready\n");
    rte_eal_mp_wait_lcore();
    /* cleanup resources */
    doca_flow_destroy();
    dpdk_queues_and_ports_fini(&dpdk_config);
    dpdk_fini();
    /* ARGP cleanup */
    doca_argp_destroy();
    return exit_status;
}

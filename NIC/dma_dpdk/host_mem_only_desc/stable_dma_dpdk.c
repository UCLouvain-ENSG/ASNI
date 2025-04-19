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
#include <netdb.h>
#include <rte_memory.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>

#include "udp_comm.h"
#include "utils.h"
#include <../../../utils/receive_data_from_host.h>
#include <../../../utils/set_dma_buffer.h>
#include <signal.h>

// DOCA

#include "asq_descriptors.h"
#include "consts.h"
#include "dma_common.h"
#include "dma_exchange.h"
#include "dma_jobs.h"
#include "dpdk_utils2.h"
#include <doca_argp.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_dpdk.h>
#include <doca_error.h>
#include <doca_log.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

/*Includes for the direct payload transfer*/
#include "mlx5_common.h"
#include "mlx5_common_mr.h"
#include <doca_rdma_bridge.h>

DOCA_LOG_REGISTER(DMA_DPDK::MAIN);

// #define SLEEP_IN_NANOS (10 * 1000)	/* Sample the job every 10 microseconds
// */
#define SLEEP_IN_NANOS (100) /* Sample the job every 10 nanocroseconds  */
#define RECV_BUF_SIZE 256    /* Buffer which contains config information */

#define WORKQ_DEPTH                                                            \
    2048 /* Work queue depth : MAY CAUSE CRASH IF TOO LOW (be cause we don't   \
          * wait for termination) if WORKQ_DEPTH < DESCRIPTOR_NB, too many dma \
          * jobs may saturate the queue                                        \
          * /!\ REDEFINITION of value defined in dma_common.h /!               \
          */
#define PCIE_ADDR "03:00.0"

#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

// DPDK

#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024 /* The size of each RX queue */

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE                                                             \
    48 /* Has to be lower than the number of descriptor in the ring */
#define DESCRIPTOR_NB                                                          \
    2048 /* The number of descriptor in the ring (MAX uint16_t max val or      \
            change curr_head-tail type) */
#define NB_PORTS 1
#define DMA_MAX_WINDOW 5

// Declaring DMA structure globally
#define MAX_NB_CORES 32

// A queue containing every job states on the fly
struct program_core_objects *flying_states[MAX_NB_CORES][DMA_MAX_WINDOW];
// A queue containing every job events on the fly
struct doca_event flying_events[MAX_NB_CORES][DMA_MAX_WINDOW];
// Reading head
uint8_t flying_head[MAX_NB_CORES] = {0};
// Current number of job on the fly
uint8_t flying_nb[MAX_NB_CORES] = {0};

static volatile bool force_quit = false;
static uint32_t nb_core = 1; /* The number of Core working (max 7) */
bool payload_transfer_on = false;
bool direct_payload_transfer = false;

// attribute packed
struct arguments {
    struct doca_pci_bdf *pcie_addr;
    uint16_t port;
    uint16_t lcore_index;
};

struct rte_mempool *mbufs_pools[MAX_NB_CORES];

struct program_core_objects state_desc[MAX_NB_CORES] = {0};
struct doca_dma *dma_ctx_desc[MAX_NB_CORES];
struct doca_buf ***src_doca_buf_desc;
struct doca_buf *dst_doca_buf_desc[MAX_NB_CORES];
struct doca_mmap *remote_mmap_desc[MAX_NB_CORES];
struct doca_dma_job_memcpy dma_job_read_desc[MAX_NB_CORES] = {0};
struct doca_dma_job_memcpy dma_job_write_desc[MAX_NB_CORES] = {0};
size_t local_buffer_size_desc[MAX_NB_CORES];
char export_desc_desc[MAX_NB_CORES][1024] = {0};
char *remote_addr_desc[MAX_NB_CORES] = {0};
size_t remote_addr_len_desc[MAX_NB_CORES] = {0},
       export_desc_len_desc[MAX_NB_CORES] = {0};
struct dma_resources resources_desc[MAX_NB_CORES];
struct dma_resources resources_payload[MAX_NB_CORES];

uint64_t pos_desc = 0;
char *ring_desc[MAX_NB_CORES];
size_t size_desc[MAX_NB_CORES];
size_t payload_pointer[MAX_NB_CORES];
size_t max_payload_size[MAX_NB_CORES];
dma_job_struct_t jobs[64];

// Payloads
struct program_core_objects state_payloads[MAX_NB_CORES] = {0};
struct doca_dma *dma_ctx_payloads[MAX_NB_CORES];
struct doca_buf ***src_doca_buf_payloads;
struct doca_buf *dst_doca_buf_payloads[MAX_NB_CORES];
struct doca_mmap *remote_mmap_payloads[MAX_NB_CORES];
struct doca_dma_job_memcpy dma_job_read_payloads[MAX_NB_CORES] = {0};
struct doca_dma_job_memcpy dma_job_write_payloads[MAX_NB_CORES] = {0};
size_t local_buffer_size_payloads[MAX_NB_CORES];
char export_desc[MAX_NB_CORES][1024] = {0};
char *remote_addr_payloads[MAX_NB_CORES] = {0};
size_t remote_addr_len[MAX_NB_CORES] = {0}, export_desc_len[MAX_NB_CORES] = {0};

uint64_t pos_payloads[MAX_NB_CORES] = {0};
char *ring_payloads[MAX_NB_CORES];
size_t size_payloads[MAX_NB_CORES];

#define MAX_DMA_BUF_SIZE                                                       \
    BURST_SIZE * sizeof(struct descriptor) /* DMA buffer maximum size          \
                                            */

static void signal_handler(int signum) {
    if (force_quit) {
        printf("Forcing exit\n");
        exit(0);
    }
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit\nPress again to "
               "force exit\n",
               signum);
        force_quit = true;
    }
}

/* Main functional part of port initialization. 8< */

static void init_port(int port_id) {
    int ret;
    uint16_t i;
    /* Ethernet port configured with default settings. 8< */
    static struct rte_eth_conf port_conf = {
        .rxmode =
            {
                .mq_mode = RTE_ETH_MQ_RX_RSS,
                //.offloads = DEV_RX_OFFLOAD_SCATTER,
            },
        .rx_adv_conf =
            {
                .rss_conf =
                    {
                        .rss_key = NULL,
                        .rss_hf =
                            RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
                    },
            },
        .txmode =
            {
                .mq_mode = RTE_ETH_MQ_TX_NONE,
            },
    };
    struct rte_eth_txconf txq_conf;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_dev_info dev_info;

    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0)
        rte_exit(EXIT_FAILURE,
                 "Error during getting device (port %u) info: %s\n", port_id,
                 strerror(-ret));

    port_conf.txmode.offloads &= dev_info.tx_offload_capa;
    printf(":: initializing port: %d\n", port_id);
    ret = rte_eth_dev_configure(port_id, nb_core, nb_core, &port_conf);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, ":: cannot configure device: err=%d, port=%u\n",
                 ret, port_id);
    }

    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;
    /* >8 End of ethernet port configured with default settings. */

    /* Configuring number of RX and TX queues connected to single port. 8< */
    for (i = 0; i < nb_core; i++) {
        ret = rte_eth_rx_queue_setup(port_id, i, RTE_TEST_RX_DESC_DEFAULT,
                                     rte_eth_dev_socket_id(port_id), &rxq_conf,
                                     mbufs_pools[i]);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE,
                     ":: Rx queue setup failed: err=%d, port=%u\n", ret,
                     port_id);
        }
    }

    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.txmode.offloads;

    for (i = 0; i < nb_core; i++) {
        ret = rte_eth_tx_queue_setup(port_id, i, RTE_TEST_TX_DESC_DEFAULT,
                                     rte_eth_dev_socket_id(port_id), &txq_conf);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE,
                     ":: Tx queue setup failed: err=%d, port=%u\n", ret,
                     port_id);
        }
    }
    /* >8 End of Configuring RX and TX queues connected to single port. */

    /* Setting the RX port to promiscuous mode. 8< */
    ret = rte_eth_promiscuous_enable(port_id);
    if (ret != 0)
        rte_exit(EXIT_FAILURE,
                 ":: promiscuous mode enable failed: err=%s, port=%u\n",
                 rte_strerror(-ret), port_id);
    /* >8 End of setting the RX port to promiscuous mode. */

    /* Starting the port. 8< */
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", ret,
                 port_id);
    }
    /* >8 End of starting the port. */
    printf(":: initializing port: %d done\n", port_id);
}

/**
 * @brief Wait for the oldest job to complete
 *
 * @return uint8_t 0 if no job to wait, 1 if success, 2 if failed to retrieve, 3
 * if job failed
 */
uint8_t wait_dma(struct dma_copy_resources *resources) {
    struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = SLEEP_IN_NANOS,
    };
    struct program_core_objects *state = &resources->state;
    while (resources->run_pe_progress) {
        if (doca_pe_progress(state->pe) == 0)
            nanosleep(&ts, &ts);
    }
    return 0;
}

doca_error_t write_dma(struct dma_copy_resources *resources, struct timespec ts,
                       struct doca_buf *src_buf, struct doca_buf *dst_buf) {
    doca_error_t result;
    doca_error_t task_result;
    union doca_data task_user_data = {0};
    struct doca_dma_task_memcpy *dma_task = NULL;
    struct doca_task *task;
    // If there is already to much job on the fly, wait for the oldest to
    // complete
    task_user_data.ptr = &task_result;
    result = doca_dma_task_memcpy_alloc_init(resources->dma_ctx, src_doca_buf,
                                             dst_doca_buf, task_user_data,
                                             &dma_task);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to allocate DMA memcpy task: %s",
                     doca_error_get_descr(result));
        return result;
    }
    task = doca_dma_task_memcpy_as_task(dma_task);
    /* DOCA : Enqueue DMA job */
    result = doca_task_submit(task);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to submit DMA task: %s",
                     doca_error_get_descr(result));
    }
    while (result == DOCA_ERROR_NO_MEMORY) {
        DOCA_LOG_ERR("Failed to submit DMA task: %s\n",
                     doca_error_get_descr(result));
        wait_dma(resources);
        result = doca_task_submit(task);
    }
    return DOCA_SUCCESS;
}

doca_error_t read_dma(struct doca_dma_job_memcpy dma_job,
                      struct program_core_objects state, struct timespec ts,
                      struct doca_event event) {
    doca_error_t result;

    /* DOCA : Enqueue DMA job */
    result = doca_workq_submit(state.workq, &dma_job.base);
    while (result == DOCA_ERROR_NO_MEMORY) {
        while ((result = doca_workq_progress_retrieve(
                    state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
               DOCA_ERROR_AGAIN) {
            // nanosleep(&ts, &ts);
        }
        result = doca_workq_submit(state.workq, &dma_job.base);
    }
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to submit DMA job: %s",
                     doca_error_get_descr(result));
        return result;
    }
    /* DOCA : Wait for job completion */
    while ((result = doca_workq_progress_retrieve(
                state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
           DOCA_ERROR_AGAIN) {
        // nanosleep(&ts, &ts);
    }
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to retrieve DMA job: %s",
                     doca_error_get_descr(result));
        return result;
    }

    result = (doca_error_t)event.result.u64;
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("DMA job event returned unsuccessfully: %s",
                     doca_error_get_descr(result));
        return result;
    }

    return DOCA_SUCCESS;
}

/*
 * Run DOCA DMA DPU copy sample
 *
 * @export_desc_file_path [in]: Export descriptor file path
 * @buffer_info_file_path [in]: Buffer info file path
 * @pcie_addr [in]: Device PCI address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */

static int job(void *arg) {
    // args
    struct arguments *args = (struct arguments *)arg;
    struct doca_pci_bdf *pcie_addr = args->pcie_addr;
    uint16_t port = args->port;
    uint16_t lcore_index = args->lcore_index;
    printf("lcore_index : %d\n", lcore_index);

    doca_error_t result;
    struct timespec ts = {0};
    // Descriptors
    uint64_t pos_desc = 0;
    uint64_t pos_payloads = 0;
    int pkt_counter = 0;

    // Data
    struct timeval start;
    bool has_received_first_packet = false;

    /* DOCA : Create DMA context */
    /* Initializing descriptor ring buffer */
    /* Initializing payload_buffer*/

    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());

#ifdef HAVE_CYCLE
    uint64_t start_cycle = 0;
    uint64_t end_cycle = 0;
    uint64_t total_usefull_cycles = 0;
    uint64_t tmp_start = 0;
    uint64_t tmp_end = 0;
    uint64_t pkt_processed = 0;
#endif
    /* DOCA : Construct DMA job */
    /* Descriptors */
    // dma_job_write_desc[lcore_index].base.type = DOCA_DMA_JOB_MEMCPY;
    // dma_job_write_desc[lcore_index].base.flags = DOCA_JOB_FLAGS_NONE;
    // dma_job_write_desc[lcore_index].base.ctx = state_desc[lcore_index].ctx;
    // dma_job_write_desc[lcore_index].dst_buff =
    // dst_doca_buf_desc[lcore_index]; dma_job_write_desc[lcore_index].src_buff
    // =
    //     src_doca_buf_desc[lcore_index][0];
    //
    // dma_job_read_desc[lcore_index].base.type = DOCA_DMA_JOB_MEMCPY;
    // dma_job_read_desc[lcore_index].base.flags = DOCA_JOB_FLAGS_NONE;
    // dma_job_read_desc[lcore_index].base.ctx = state_desc[lcore_index].ctx;
    // dma_job_read_desc[lcore_index].dst_buff =
    // src_doca_buf_desc[lcore_index][0];
    // dma_job_read_desc[lcore_index].src_buff = dst_doca_buf_desc[lcore_index];

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    struct rte_mbuf *rte_mbufs[BURST_SIZE];
    struct descriptor *descriptors =
        (struct descriptor *)ring_desc[lcore_index];
    struct descriptor *remote_descriptors =
        (struct descriptor *)remote_addr_desc[lcore_index];

    uint64_t counter = 0;
    uint64_t timestamp = 0;
    uint64_t old_pos = 0;
    uint64_t new_pos = 0;
    uint64_t payload_offset = 0;
    uint64_t copy_length_tracker = 0;
    struct doca_buf *first_element = src_doca_buf_payloads[lcore_index][0];
    struct doca_buf *curr_head = src_doca_buf_payloads[lcore_index][0];
    struct doca_buf *holder;
    uint32_t nb_elements;
    result = doca_buf_list_num_elements(curr_head, &nb_elements);
    printf("nb_elements : %u\n", nb_elements);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to get length : %s",
                     doca_error_get_descr(result));
        return EXIT_FAILURE;
    }
    uint64_t bytes_counter = 0;
    uint64_t start_time = 0;
    /* Main work of application loop */
    for (;;) {
        /* Payload jobs */
        int job_index = 0;

        /* Quit the app on Control+C */
        if (force_quit) {
            double time_elapsed =
                (double)(rte_get_tsc_cycles() - start_time) / rte_get_tsc_hz();
            printf("\n\nTroughput for core %u : %f Gbps\n", lcore_index,
                   (bytes_counter * 8) / time_elapsed / 1000000000);

#ifdef HAVE_CYCLE
            printf("RESULT-CYCLES-PER-PACKET-NIC %lf\n",
                   (double)total_usefull_cycles / (double)pkt_processed);
#endif
            printf("Exiting on core : %d\n", rte_lcore_id());
            wait_dma(&resources_desc[lcore_index]);
            printf("DMA jobs completed\n");
            // Get the number of packets dropped by the NIC
            struct rte_eth_stats stats;
            rte_eth_stats_get(port, &stats);
            printf("Packets dropped by NIC : %lu\n", stats.imissed);

            printf("\nCore %u pos : %lu counter : %ld\n", rte_lcore_id(),
                   pos_desc, counter);

            /* DOCA : Clean allocated memory */
            if (doca_buf_dec_refcount(src_doca_buf_desc[lcore_index][0],
                                      NULL) != DOCA_SUCCESS)
                DOCA_LOG_ERR(
                    "Failed to remove DOCA source buffer reference count");
            if (doca_buf_dec_refcount(dst_doca_buf_desc[lcore_index], NULL) !=
                DOCA_SUCCESS)
                DOCA_LOG_ERR(
                    "Failed to remove DOCA destination buffer reference count");

            if (doca_buf_dec_refcount(src_doca_buf_payloads[lcore_index][0],
                                      NULL) != DOCA_SUCCESS)
                DOCA_LOG_ERR(
                    "Failed to remove DOCA source buffer reference count");
            if (doca_buf_dec_refcount(dst_doca_buf_payloads[lcore_index],
                                      NULL) != DOCA_SUCCESS)
                DOCA_LOG_ERR(
                    "Failed to remove DOCA destination buffer reference count");
            /* DOCA : Destroy remote memory map */
            if (doca_mmap_destroy(remote_mmap_desc[lcore_index]) !=
                DOCA_SUCCESS)
                DOCA_LOG_ERR("Failed to destroy remote memory map");
            if (doca_mmap_destroy(remote_mmap_payloads[lcore_index]) !=
                DOCA_SUCCESS)
                DOCA_LOG_ERR("Failed to destroy remote memory map");
            /* DOCA : Inform host that DMA operation is done */
            DOCA_LOG_INFO("DMA cleaned up");

            /* DOCA : Clean and destroy all relevant objects */
            dma_cleanup(&state_desc[lcore_index], dma_ctx_desc[lcore_index]);

            rte_free(ring_desc[lcore_index]);

            dma_cleanup(&state_payloads[lcore_index],
                        dma_ctx_payloads[lcore_index]);

            rte_free(ring_payloads[lcore_index]);

            return result;
        }

        /* DPDK : Get burst of RX packets from the port */
        // printf("before rx_burst\n");
        // printf("lcore_index : %d\n", lcore_index);
#ifdef HAVE_CYCLE
        tmp_start = rte_get_tsc_cycles();
#endif

        const uint16_t nb_rx =
            rte_eth_rx_burst(port, lcore_index, rte_mbufs, BURST_SIZE);

        if (nb_rx == 0) {
            continue;
        }
        pkt_counter += nb_rx;
        /* Data : Start the timer */
        if (counter > 0 && !has_received_first_packet) {
            gettimeofday(&start, NULL);
            start_time = rte_get_tsc_cycles();
            has_received_first_packet = true;
        }

        old_pos = pos_desc;
        new_pos = (pos_desc + nb_rx) % DESCRIPTOR_NB;

        for (int i = 0; i < nb_rx; i++) {
            size_t payload_length = rte_mbufs[i]->data_len;
            bytes_counter += payload_length;
// Parse headers only if needed
#if defined FAKE_DPDK_DESC_IP_SRC || defined FAKE_DPDK_DESC_IP_DST
            struct rte_ether_hdr *eth_hdr =
                (struct rte_ether_hdr *)(rte_pktmbuf_mtod(rte_mbufs[i],
                                                          char *));
            if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                struct rte_ipv4_hdr *ip_hdr;
                struct rte_tcp_hdr *tcp_hdr;
                ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(rte_mbufs[i],
                                                                  char *) +
                                                 sizeof(struct rte_ether_hdr));
#if defined FAKE_DPDK_DESC_IP_SRC
                descriptors[pos_desc].ip_src = ip_hdr->src_addr;
#endif
#if defined FAKE_DPDK_DESC_IP_DST
                descriptors[pos_desc].ip_dst = ip_hdr->dst_addr;
#endif
            }
#endif
            counter++;
            timestamp++;
            *(uint64_t *)rte_mbufs[i]->buf_addr = payload_offset;
            descriptors[pos_desc].full = 1;
#ifdef FAKE_DPDK_DESC_TIMESTAMP
            descriptors[pos_desc].timestamp = timestamp;
#endif
#ifdef FAKE_DPDK_DESC_PAYLOAD
            descriptors[pos_desc].payload_ptr =
                remote_addr_payloads[lcore_index] + payload_offset;
#endif
#ifdef FAKE_DPDK_DESC_SIZE
            descriptors[pos_desc].size = rte_mbufs[i]->data_len;
#endif
#ifdef FAKE_DPDK_DESC_HASH
            descriptors[pos_desc].rss_hash = rte_mbufs[i]->hash.rss;
#endif
            copy_length_tracker += payload_length;
            if (payload_transfer_on) {
                if ((payload_offset + copy_length_tracker) >
                    PAYLOAD_ARRAY_SIZE) {
                    /*first iteration, nothing to do apart from reseting
                     * offset*/
                    if (curr_head == first_element) {
                        payload_offset = 0;
                    } else {
                        /*Not the first iteration we should flush the list*/
                        result = doca_buf_list_next(curr_head, &holder);
                        if (result != DOCA_SUCCESS) {
                            DOCA_LOG_ERR("Failed to get next elements: %s",
                                         doca_error_get_descr(result));
                            return EXIT_FAILURE;
                        }
                        if (holder == NULL) {
                            printf("nb_rx : %d\n", i);
                            printf("End of list, this should never happend1\n");
                        } else {
                            curr_head = holder;
                        }
                        result =
                            doca_buf_list_unchain(first_element, curr_head);
                        if (result != DOCA_SUCCESS) {
                            DOCA_LOG_ERR("Failed to unchain lists: %s",
                                         doca_error_get_descr(result));
                            return EXIT_FAILURE;
                        }
                        result = doca_buf_set_data(
                            dst_doca_buf_payloads[lcore_index],
                            remote_addr_payloads[lcore_index] + payload_offset,
                            copy_length_tracker);
                        if (result != DOCA_SUCCESS) {
                            DOCA_LOG_ERR(
                                "Failed to set data for DOCA buffer: %s",
                                doca_error_get_descr(result));
                            return EXIT_FAILURE;
                        }
                        if (payload_transfer_on) {
                            result = submit_job_sync(
                                &state_payloads[lcore_index], first_element,
                                dst_doca_buf_payloads[lcore_index]);
                            if (result != DOCA_SUCCESS) {
                                DOCA_LOG_ERR("Failed to submit job: %s",
                                             doca_error_get_descr(result));
                                return EXIT_FAILURE;
                            }
                        }
                        result = doca_buf_list_chain(first_element, curr_head);
                        if (result != DOCA_SUCCESS) {
                            DOCA_LOG_ERR("Failed to unchain lists: %s",
                                         doca_error_get_descr(result));
                            return EXIT_FAILURE;
                        }
                    }
                    copy_length_tracker = 0;
                    payload_offset = 0;
                }
                result = doca_buf_set_data(curr_head, rte_mbufs[i]->buf_addr,
                                           payload_length);
                if (result != DOCA_SUCCESS) {
                    DOCA_LOG_ERR("Failed to set data for DOCA buffer: %s",
                                 doca_error_get_descr(result));
                    return EXIT_FAILURE;
                }

                copy_length_tracker += payload_length;

                result = doca_buf_list_next(curr_head, &holder);
                if (result != DOCA_SUCCESS) {
                    DOCA_LOG_ERR("Failed to get next elements: %s",
                                 doca_error_get_descr(result));
                    return EXIT_FAILURE;
                }
                if (holder == NULL) {
                    printf("nb_rx : %d\n", i);
                    printf("End of list, this should never happend2\n");
                } else {
                    curr_head = holder;
                }
                payload_offset += payload_length;
            }
            pos_desc++;
            if (pos_desc == DESCRIPTOR_NB)
                pos_desc = 0;
        }
        if (payload_transfer_on) {
            if (first_element != curr_head) {
                result = doca_buf_list_unchain(first_element, curr_head);
                if (result != DOCA_SUCCESS) {
                    DOCA_LOG_ERR("Failed to unchain lists: %s",
                                 doca_error_get_descr(result));
                    return EXIT_FAILURE;
                }
                result = doca_buf_set_data(dst_doca_buf_payloads[lcore_index],
                                           remote_addr_payloads[lcore_index] +
                                               payload_offset,
                                           copy_length_tracker);
                if (result != DOCA_SUCCESS) {
                    DOCA_LOG_ERR("Failed to set data for DOCA buffer: %s",
                                 doca_error_get_descr(result));
                    return EXIT_FAILURE;
                }
                copy_length_tracker = 0;

                if (payload_transfer_on) {
                    result = submit_job_sync(
                        &state_payloads[lcore_index], first_element,
                        dst_doca_buf_payloads[lcore_index]);
                    if (result != DOCA_SUCCESS) {
                        DOCA_LOG_ERR("Failed to submit job: %s",
                                     doca_error_get_descr(result));
                        return EXIT_FAILURE;
                    }
                }

                // Reconstructing the linked list
                result = doca_buf_list_chain(first_element, curr_head);
                if (result != DOCA_SUCCESS) {
                    DOCA_LOG_ERR("Failed to unchain lists: %s",
                                 doca_error_get_descr(result));
                    return EXIT_FAILURE;
                }
                curr_head = first_element;
            }
        }
        rte_pktmbuf_free_bulk(rte_mbufs, nb_rx);

#ifdef HAVE_CYCLE

        tmp_end = rte_get_tsc_cycles();
        // printf("cycle requiered : %lu\n", (tmp_end) - (tmp_start));
        // printf("nb_rx : %lu\n", nb_rx);
        total_usefull_cycles += tmp_end - tmp_start;
        // printf("total_usefull_cycles : %lu\n", total_usefull_cycles);
        pkt_processed += (uint64_t)nb_rx;
        // printf("pkt_processed : %lu\n", pkt_processed);
#endif
        // If descriptor ringbuffer didn't wrap around, simply send nb_rx
        // descriptors
        if (old_pos + nb_rx <= DESCRIPTOR_NB) {
            set_buf_write(src_doca_buf_desc[lcore_index][0],
                          dst_doca_buf_desc[lcore_index],
                          &remote_descriptors[old_pos], &descriptors[old_pos],
                          nb_rx * sizeof(struct descriptor));

            result = write_dma(dma_job_write_desc[lcore_index],
                               state_desc[lcore_index], ts, lcore_index);
            if (result != DOCA_SUCCESS) {
                printf("Core %d crashed while writing buffer\n",
                       rte_lcore_id());
                goto cleaner;
                return EXIT_FAILURE;
            }
            // If it wrapped around, send the first part of the descriptors and
            // then the second part
        } else {
            // Send the end of the ringbuffer before it wrapped around
            set_buf_write(src_doca_buf_desc[lcore_index][0],
                          dst_doca_buf_desc[lcore_index],
                          &remote_descriptors[old_pos], &descriptors[old_pos],
                          (DESCRIPTOR_NB - old_pos) *
                              sizeof(struct descriptor));

            result = write_dma(dma_job_write_desc[lcore_index],
                               state_desc[lcore_index], ts, lcore_index);

            if (result != DOCA_SUCCESS) {
                printf("Core %d crashed while writing buffer first part\n",
                       rte_lcore_id());
                goto cleaner;
                return EXIT_FAILURE;
            }
            // Send the beginning of the ringbuffer, after it wrapped around
            set_buf_write(
                src_doca_buf_desc[lcore_index][0],
                dst_doca_buf_desc[lcore_index], remote_descriptors, descriptors,
                (old_pos + nb_rx - DESCRIPTOR_NB) * sizeof(struct descriptor));

            result = write_dma(dma_job_write_desc[lcore_index],
                               state_desc[lcore_index], ts, lcore_index);
            if (result != DOCA_SUCCESS) {
                printf("Core %d crashed while writing buffer second part\n",
                       rte_lcore_id());
                goto cleaner;
                return EXIT_FAILURE;
            }
        }
    }

cleaner:
    // descriptors
    doca_buf_dec_refcount(dst_doca_buf_desc[lcore_index], NULL);
    doca_buf_dec_refcount(src_doca_buf_desc[lcore_index][0], NULL);
    doca_mmap_destroy(remote_mmap_desc[lcore_index]);
    rte_free(ring_desc[lcore_index]);
    dma_cleanup(&state_desc[lcore_index], dma_ctx_desc[lcore_index]);

    // payloads
    doca_buf_dec_refcount(dst_doca_buf_payloads[lcore_index], NULL);
    doca_buf_dec_refcount(src_doca_buf_payloads[lcore_index][0], NULL);
    doca_mmap_destroy(remote_mmap_payloads[lcore_index]);
    rte_free(ring_payloads[lcore_index]);
    dma_cleanup(&state_payloads[lcore_index], dma_ctx_payloads[lcore_index]);
}

int option(int argc, char **argv) {

    int c;

    while (1) {
        static struct option long_options[] = {
            /* These options set a flag. */
            {"dma_desc_payl", no_argument, (int *)&payload_transfer_on, true},
            {"dma_desc_only", no_argument, (int *)&payload_transfer_on, false},
            {"dma_desc_dpdk_payl", no_argument, (int *)&direct_payload_transfer,
             true},
        };
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "c:", long_options, &option_index);

        if (c == -1)
            break;

        /* Detect the end of the options. */
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
            break;
        default:
            abort();
        }
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
 * Sample main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int main(int argc, char **argv) {

    // DOCA
    struct doca_pci_bdf pcie_dev;
    int result;
    doca_error_t doca_result;

    /* logger */
    struct doca_logger_backend *stdout_logger = NULL;

    /* Create a logger backend that prints to the standard output */
    result = doca_log_create_file_backend(stdout, &stdout_logger);
    if (result != DOCA_SUCCESS)
        return EXIT_FAILURE;

    // args
    struct arguments args[64];

    // DPDK
    uint16_t lcore_id;
    uint16_t portid;

    /* DPDK : Initializion the Environment Abstraction Layer (EAL) */
    result = rte_eal_init(argc, argv);
    if (result < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= result;
    argv += result;

    result = option(argc, argv);
    if (result == -1)
        return -1;

    printf("Number of core enabled : %d\n", nb_core);

    /* DOCA : */
    result = doca_pci_bdf_from_string(PCIE_ADDR, &pcie_dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to parse pci address: %s",
                     doca_error_get_descr(result));
        return EXIT_FAILURE;
    }

    /* MAIN : polling each queue on a lcore */
    int index = 0;
    int udp_port = 0;
    int nb_doca_bufs = BURST_SIZE + 5;
    // Allocating source doca_bufs for linked lists
    src_doca_buf_payloads =
        rte_malloc(NULL, sizeof(struct doca_buf ***) * nb_doca_bufs, 0);
    src_doca_buf_desc =
        rte_malloc(NULL, sizeof(struct doca_buf ***) * nb_doca_bufs, 0);
    for (int i = 0; i < nb_doca_bufs; i++) {
        src_doca_buf_payloads[i] =
            rte_malloc(NULL, sizeof(struct doca_buf **) * nb_doca_bufs, 0);
        src_doca_buf_desc[i] =
            rte_malloc(NULL, sizeof(struct doca_buf **) * nb_doca_bufs, 0);
    }

    for (int i = 0; i < nb_doca_bufs; i++) {
        for (int j = 0; j < nb_doca_bufs; j++) {
            src_doca_buf_desc[i][j] =
                rte_malloc(NULL, sizeof(struct doca_buf *) * nb_doca_bufs, 0);
            src_doca_buf_payloads[i][j] =
                rte_malloc(NULL, sizeof(struct doca_buf *) * nb_doca_bufs, 0);
        }
    }
    for (int i = 0; i < nb_core; i++) {
        doca_result = dma_import_memory(
            &pcie_dev, &ring_desc[index], &local_buffer_size_desc[index],
            &remote_addr_desc[index], &state_desc[index],
            src_doca_buf_desc[index], nb_doca_bufs, &dst_doca_buf_desc[index],
            &remote_mmap_desc[index], &resources_desc[index], udp_port++);
        if (doca_result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to create DMA engine: %s",
                         doca_error_get_descr(doca_result));
            return doca_result;
        }
        if (doca_result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to create DMA engine: %s",
                         doca_error_get_descr(doca_result));
            return doca_result;
        }
        doca_result = dma_import_memory(
            &pcie_dev, &ring_payloads[index],
            &local_buffer_size_payloads[index], &remote_addr_payloads[index],
            &state_payloads[index], src_doca_buf_payloads[index], nb_doca_bufs,
            &dst_doca_buf_payloads[index], &remote_mmap_payloads[index],
            &resources_payload[index], udp_port++);
        if (doca_result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to create DMA engine: %s",
                         doca_error_get_descr(doca_result));
            return doca_result;
        }
        for (int j = 1; j < nb_doca_bufs; j++) {
            doca_result = doca_buf_list_chain(src_doca_buf_payloads[index][0],
                                              src_doca_buf_payloads[index][j]);
            if (doca_result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Unable to create DMA engine: %s",
                             doca_error_get_descr(doca_result));
                return EXIT_FAILURE;
            }
        }
        index++;
    }
    struct rte_pktmbuf_extmem ext_mem[64];
    char mbuf_pool_name[] = "MBUF_POOL_X";
    uint32_t mkey;
    struct ibv_pd *pd;

    for (int i = 0; i < nb_core; i++) {
        mbuf_pool_name[strlen(mbuf_pool_name) - 1] = 48 + i;
        if (direct_payload_transfer) {
            doca_result = doca_buf_get_mkey(dst_doca_buf_payloads[i],
                                            state_payloads[i].dev, &mkey);
            if (doca_result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Unable to doca_buf_get_mkey %s",
                             doca_error_get_descr(doca_result));
                return doca_result;
            }
            doca_result = doca_dev_get_pd(state_payloads[i].dev, &pd);
            if (doca_result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Unable to get pd %s",
                             doca_error_get_descr(doca_result));
                return doca_result;
            }
            ext_mem[i].elt_size = RTE_MBUF_DEFAULT_BUF_SIZE;
            ext_mem[i].buf_len = local_buffer_size_payloads[i];
            ext_mem[i].buf_iova = RTE_BAD_IOVA;
            ext_mem[i].buf_ptr = remote_addr_payloads[i];
            mbufs_pools[i] = rte_pktmbuf_pool_create_extbuf(
                mbuf_pool_name, 1024, 0, 0, ext_mem[i].elt_size,
                rte_socket_id(), &ext_mem[i], 1);
            if (mbufs_pools[i] == NULL) {
                rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
            }
            rte_mempool_obj_iter(mbufs_pools[i], rte_pktmbuf_set_dynfield1,
                                 (uintptr_t)(mkey));
        } else {
            mbufs_pools[i] = rte_pktmbuf_pool_create_with_given_memory(
                mbuf_pool_name, 4096, MEMPOOL_CACHE_SIZE, 0,
                RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id(), ring_payloads[i],
                local_buffer_size_payloads[i], 1073741824);
            if (mbufs_pools[i] == NULL) {
                rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
            }
        }
    }
    if (direct_payload_transfer) {
        mlx5_set_tmp_pd(pd);
        doca_result = doca_dpdk_port_probe(state_payloads[0].dev,
                                           "representor=[0,65535]");
        if (doca_result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to probe device %s",
                         doca_error_get_descr(doca_result));
            return doca_result;
        }
    }
    printf("rte_eth_dev_count_avail : %d\n", rte_eth_dev_count_avail());

    /* DPDK Initializing the desired port. */
    // FIXME this behavior is pretty weird, ports id sometimes move randomly,
    // this can be cause by the dpdk version we are using
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
    portid = 1;
    init_port(portid);
    index = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        args[index].pcie_addr = &pcie_dev;
        args[index].port = portid;
        args[index].lcore_index = index, args[index].lcore_index = index;
        if (index < nb_core)
            rte_eal_remote_launch(job, &args[index], lcore_id);
        index++;
    }
    rte_eal_mp_wait_lcore();

    /* DPDK : clean up the EAL */
    rte_eal_cleanup();

    return EXIT_SUCCESS;
}

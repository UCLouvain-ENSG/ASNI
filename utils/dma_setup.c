

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

#include <receive_data_from_host.h>
#include <set_dma_buffer.h>
#include <signal.h>

#include "dma_setup.h"

DOCA_LOG_REGISTER(DMA_SETUP::MAIN);

/* Defining all the variables */
#define SLEEP_IN_NANOS (100) /* Sample the job every 10 nanocroseconds  */
#define RECV_BUF_SIZE 256    /* Buffer which contains config information */

#define PCIE_ADDR "03:00.0"

#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

#define MAX_DMA_BUF_SIZE                                                       \
    BURST_SIZE * sizeof(struct descriptor) /* DMA buffer maximum size          \
                                            */

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

static void init_port_dma(int port_id, int nb_core,
                          struct rte_mempool **mbufs_pools) {
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

int init_dma_nic(int portid, int nb_core, const char *pcie_addr) {

    // A queue containing every job states on the fly
    printf("inside init_dma_nic\n");
    struct program_core_objects *flying_states[MAX_NB_CORES][DMA_MAX_WINDOW];
    // A queue containing every job events on the fly
    struct doca_event flying_events[MAX_NB_CORES][DMA_MAX_WINDOW];
    uint8_t flying_head[MAX_NB_CORES] = {0};
    // Current number of job on the fly
    uint8_t flying_nb[MAX_NB_CORES] = {0};

    static volatile bool force_quit = false;
    bool direct_payload_transfer = true;

    // attribute packed
    struct arguments_dma {
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
    size_t remote_addr_len[MAX_NB_CORES] = {0},
           export_desc_len[MAX_NB_CORES] = {0};

    uint64_t pos_payloads[MAX_NB_CORES] = {0};
    char *ring_payloads[MAX_NB_CORES];
    size_t size_payloads[MAX_NB_CORES];

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
    struct arguments_dma args[64];

    // DPDK
    uint16_t lcore_id;

    /* DPDK : Initializion the Environment Abstraction Layer (EAL) */
    /* DOCA : */
    result = doca_pci_bdf_from_string(pcie_addr, &pcie_dev);
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
            &remote_mmap_desc[index], &dma_ctx_desc[index], udp_port++);
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
            &dma_ctx_payloads[index], udp_port++);
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
    char mbuf_pool_name[] = "MBUF_POOLB_X";
    uint32_t mkey;
    struct ibv_pd *pd;

    for (int i = 0; i < nb_core; i++) {
        mbuf_pool_name[strlen(mbuf_pool_name) - 1] = 48 + i;
        printf("name : %s\n", mbuf_pool_name);
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
                mbuf_pool_name, 4096, 0, 0, ext_mem[i].elt_size,
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

    // /* DPDK Initializing the desired port. */
    init_port_dma(portid, nb_core, mbufs_pools);
    return 0;
}

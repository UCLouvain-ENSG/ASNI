#include "asq.h"
#include "rte_lcore.h"
#include "stable_dma_dpdk.h"
#include <stdint.h>

#ifdef FAKE_DPDK_MODE_DPDK_ASQ_DPT
DOCA_LOG_REGISTER(ASQ);
#endif
/* Main functional part of port initialization. 8< */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool,
                            uint16_t nb_queues) {
    const uint16_t rx_rings = rte_lcore_count() - 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    int retval;
    struct rte_eth_dev_info dev_info;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    static struct rte_eth_conf port_conf = {
        .rxmode =
            {
                .mq_mode = RTE_ETH_MQ_RX_RSS,
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

int light;

int option(int argc, char **argv, struct asq_state *asq_state) {

    int c;
    int s = -1;
    while (1) {
        static struct option long_options[] = {
            /* These options set a flag. */
            {"light", no_argument, &light, 1},

        };
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "s:", long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) {
        case 0:
            /* If this option set a flag, do nothing else now. */
            if (long_options[option_index].flag != 0)
                break;
            break;

        case 's':
            s = 0;
            asq_state->macAddr1.addr_bytes[0] = (int)strtol(optarg, NULL, 16);
            asq_state->macAddr1.addr_bytes[1] =
                (int)strtol(optarg + 3, NULL, 16);
            asq_state->macAddr1.addr_bytes[2] =
                (int)strtol(optarg + 6, NULL, 16);
            asq_state->macAddr1.addr_bytes[3] =
                (int)strtol(optarg + 9, NULL, 16);
            asq_state->macAddr1.addr_bytes[4] =
                (int)strtol(optarg + 12, NULL, 16);
            asq_state->macAddr1.addr_bytes[5] =
                (int)strtol(optarg + 15, NULL, 16);
            break;

        case '?':
            /* getopt_long already printed an error message. */
            break;

        default:
            abort();
        }
    }
    asq_state->nb_core = rte_lcore_count() - 1;
    asq_state->light = light;

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

int option_dpt(int argc, char **argv, struct asq_state *state,
               char *pci_addr_str) {

    int c;
    while (1) {
        static struct option long_options[] = {
            /* These options set a flag. */
            {"light", no_argument, &light, 1},

        };
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "p:", long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) {
        case 0:
            /* If this option set a flag, do nothing else now. */
            if (long_options[option_index].flag != 0)
                break;
            break;

        case 'p':
            strcpy(pci_addr_str, optarg);
            break;

        case '?':
            /* getopt_long already printed an error message. */
            break;

        default:
            abort();
        }
    }
    state->light = light;
    state->nb_core = rte_lcore_count() - 1;

    // Check mandatory parameters:

    /* Print any remaining command line arguments (not options). */
    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s \n", argv[optind++]);
    }

    return 0;
}

#ifdef FAKE_DPDK_MODE_DPDK_ASQ_DPT
struct asq_state *asq_init_dpt(int argc, char **argv) {
    printf("Running ASQ with descriptors of size %lu\n",
           sizeof(struct descriptor));
    char pci_addr[128] = {0};
    int nb_descriptor_nb = 2048;
    /* Create a logger backend that prints to the standard output */
    doca_error_t result = doca_log_backend_create_standard();
    if (result != DOCA_SUCCESS) {
        printf("Unable to create logger backend: %s\n",
               doca_error_get_descr(result));
        return NULL;
    }
    struct asq_state *state =
        (struct asq_state *)malloc(sizeof(struct asq_state));
    struct rte_mempool *mbuf_pool;
    uint16_t portid = 0;
    state->port = 0;
    state->light = 0;
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
        return NULL;
    }
    argc -= ret;
    argv += ret;
    if (state == NULL) {
        printf("Error allocating memory for asq_state\n");
        return NULL;
    }
    if (option_dpt(argc, argv, state, pci_addr) != 0) {
        printf("Error parsing command line arguments\n");
        return NULL;
    }

    struct stable_dma_dpdk_dma_state *dma_state =
        calloc(1, sizeof(struct stable_dma_dpdk_dma_state));
    int nb_core = state->nb_core;
    // Init pci_addr
    strcpy(dma_state->pci_addr, pci_addr);
    // Init DMA
    dma_state->nb_cores = nb_core;
    dma_state->burst_size = 0;
    dma_state->last_polled_core = 0;
    dma_state->src_buffers_desc = calloc(nb_core, sizeof(char *));
    dma_state->src_buffers_size_desc = calloc(nb_core, sizeof(size_t));
    dma_state->src_buffers_payloads = calloc(nb_core, sizeof(char *));
    dma_state->src_buffers_size_payloads = calloc(nb_core, sizeof(size_t));
    dma_state->cores_positions = calloc(dma_state->nb_cores, sizeof(uint64_t));

    int udp_port = 0;
    // FIXME
    nb_core = 7;
    printf("nb_cores : %d\n", nb_core);
    for (int index = 0; index < nb_core; index++) {
        dma_state->src_buffers_size_desc[index] =
            sizeof(struct descriptor) * nb_descriptor_nb;
        dma_state->src_buffers_desc[index] = (char *)rte_malloc(
            NULL, dma_state->src_buffers_size_desc[index], 0x1000);
        // temporary
        dma_state->src_buffers_size_payloads[index] = PAYLOAD_ARRAY_SIZE;
        dma_state->src_buffers_payloads[index] = (char *)rte_malloc(
            NULL, dma_state->src_buffers_size_payloads[index], 0x1000);

        result = dma_export_memory(
            dma_state->pci_addr, dma_state->src_buffers_desc[index],
            dma_state->src_buffers_size_desc[index], udp_port++);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to create DMA engine: %s",
                         doca_error_get_descr(result));
            return NULL;
        }
        usleep(100000);
        /* DOCA : Open the relevant DOCA device */
        result = dma_export_memory(
            dma_state->pci_addr, dma_state->src_buffers_payloads[index],
            dma_state->src_buffers_size_payloads[index], udp_port++);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to create DMA engine: %s",
                         doca_error_get_descr(result));
            return NULL;
        }
        usleep(100000);
    }

    printf("Allocating huge pool\n");
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_HUGE_MBUFS * nb_core,
                                        MBUF_CACHE_SIZE, 0, RTE_HUGE_MBUF_SIZE,
                                        rte_socket_id());
    if (mbuf_pool == NULL) {
        printf("Error allocating mbuf pool\n");
        return NULL;
    }
    /* Initializing the desired port. */
    if (port_init(0, mbuf_pool, nb_core) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
    printf("\nRunning on %d cores\n", nb_core);
    return state;
}
#endif
struct asq_state *asq_init(int argc, char **argv) {
    printf("Running ASQ with descriptors of size %lu\n",
           sizeof(struct descriptor));
    struct asq_state *state = malloc(sizeof(struct asq_state));
    struct rte_mempool *mbuf_pool;
    uint16_t portid = 0;
    state->port = 0;
    state->light = 0;
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
        return NULL;
    }
    argc -= ret;
    argv += ret;
    if (state == NULL) {
        printf("Error allocating memory for asq_state\n");
        return NULL;
    }
    if (option(argc, argv, state) != 0) {
        printf("Error parsing command line arguments\n");
        return NULL;
    }
    printf("Allocating huge pool\n");
    mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_HUGE_MBUFS * state->nb_core, MBUF_CACHE_SIZE, 0,
        RTE_HUGE_MBUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        printf("Error allocating mbuf pool\n");
        return NULL;
    }
    /* Initializing the desired port. */
    if (port_init(0, mbuf_pool, state->nb_core) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
    printf("\nRunning on %d cores\n", state->nb_core);

    return state;
}

void asq_run(void *state, int (*app)(void *)) {
    rte_eal_mp_remote_launch(app, state, SKIP_MAIN);
    rte_eal_mp_wait_lcore();
    /* clean up the EAL */
    rte_eal_cleanup();
}

void asq_rx(struct asq_state *state, struct asq_iterator *iterator) {
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_rx = rte_eth_rx_burst(state->port, 0, bufs, BURST_SIZE);
    iterator->buf = bufs;
    iterator->nb_packets = 0;
    iterator->current_segment = 0;
    iterator->current_packet = 0;
    iterator->actual_pkt_received = nb_rx;
    uint8_t iterator_desc_counter = 0;
    for (int i = 0; i < nb_rx; i++) {
        uint32_t offset_desc = 16;
        uint8_t *data = rte_pktmbuf_mtod(bufs[i], uint8_t *);
        uint8_t nb_desc = *(data + offset_desc);

        if (state->light) {
            rte_prefetch0(data);
        }
        // printf("pkt_len : %d\n", bufs[i]->pkt_len);
        // printf("data_len : %d\n", bufs[i]->data_len);
        // printf("nb_desc : %d\n", nb_desc);
        if (nb_desc < 1 || nb_desc > 64) {
            printf("=============\n");
            printf("Invalid descriptor number: %d\n", nb_desc);

            printf("=============\n");
            rte_pktmbuf_free(bufs[i]);
        } else {
            iterator->nb_desc[iterator_desc_counter] = nb_desc;
            iterator->nb_packets += iterator->nb_desc[iterator_desc_counter];
            iterator->desc[iterator_desc_counter] =
                (struct descriptor *)(data + offset_desc);
            iterator_desc_counter++;
            rte_pktmbuf_free(bufs[i]);
        }
    }
}

struct asq_iterator *asq_init_iterator(uint16_t burst_size) {
    struct asq_iterator *iterator = calloc(1, sizeof(struct asq_iterator));
    iterator->buf = calloc(burst_size, sizeof(struct rte_mbuf *));
    iterator->desc = calloc(burst_size, sizeof(struct descriptor *));
    iterator->nb_desc = calloc(burst_size, sizeof(uint8_t));
    return iterator;
}
struct descriptor *asq_get_next(struct asq_iterator *iterator) {
    // Check if we finished a segment
    if (iterator->current_packet ==
        iterator->nb_desc[iterator->current_segment]) {
        iterator->current_segment++;
        iterator->current_packet = 0;
    }
    // Check if we finished the burst
    if (iterator->current_segment == iterator->actual_pkt_received) {
        return NULL;
    }
    // Return the next descriptor
    struct descriptor *desc =
        iterator->desc[iterator->current_segment] + iterator->current_packet;
    iterator->current_packet++;
    return desc;
}

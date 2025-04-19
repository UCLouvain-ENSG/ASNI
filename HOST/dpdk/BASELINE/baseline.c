#include "baseline.h"

#if  defined(FAKE_DPDK_DESC_PAD) && defined(FAKE_DPDK_MODE_DPDK_BASELINE)
int dynfield_offset = -1;
struct rte_mempool* pad_pool = 0;
#endif

DOCA_LOG_REGISTER(BASELINE);
/* Main functional part of port initialization. 8< */
int light;
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    const uint16_t rx_rings = (rte_lcore_count() - 1);
    printf("NB_RX_RINGS : %d\n", rx_rings);
    uint16_t nb_rxd = RX_RING_SIZE_BASELINE;
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

#ifdef HAVE_MPRQ
// #    retval = rte_eth_dev_set_mtu(port, 1514);
// #    if (retval != 0)
// #        return retval;
#endif
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, NULL);
    if (retval != 0)
        return retval;

#if  defined(FAKE_DPDK_DESC_PAD) && defined(FAKE_DPDK_MODE_DPDK_BASELINE)
    static const struct rte_mbuf_dynfield dynfield_desc = {
        .name = "example_dynfield",
        .size = FAKE_DPDK_DESC_PAD > 32? sizeof(void*) : FAKE_DPDK_DESC_PAD ,
        .align = 4,
    };

    printf("Registering dynfield\n");
        dynfield_offset =
            rte_mbuf_dynfield_register(&dynfield_desc);
    if (FAKE_DPDK_DESC_PAD > 32) {
        pad_pool = rte_mempool_create("pad_pool", 2048, FAKE_DPDK_DESC_PAD, 32, 0, 0, 0,0 ,0 ,0 ,0);
        if (!pad_pool) {
            printf("Could not alloc pool\n");
            abort();
        }

    }
#endif

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

int option_baseline(int argc, char **argv, struct baseline_state *state) {

    int c;
    int s = -1;
    while (1) {

        /* getopt_long stores the option_baseline index here. */
        int option_index = 0;
        static struct option long_options[] = {
            /* These options set a flag. */
            {"light", no_argument, &light, 1},

        };
        c = getopt_long(argc, argv, "c:s:", long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) {
        case 0:
            /* If this option_baseline set a flag, do nothing else now. */
            if (long_options[option_index].flag != 0)
                break;
            break;
        case 'c':
            state->nb_core = atoi(optarg);
            break;

        case 's':
            s = 0;
            state->macAddr1.addr_bytes[0] = (int)strtol(optarg, NULL, 16);
            state->macAddr1.addr_bytes[1] = (int)strtol(optarg + 3, NULL, 16);
            state->macAddr1.addr_bytes[2] = (int)strtol(optarg + 6, NULL, 16);
            state->macAddr1.addr_bytes[3] = (int)strtol(optarg + 9, NULL, 16);
            state->macAddr1.addr_bytes[4] = (int)strtol(optarg + 12, NULL, 16);
            state->macAddr1.addr_bytes[5] = (int)strtol(optarg + 15, NULL, 16);
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
        printf("non-option_baseline ARGV-elements: ");
        while (optind < argc)
            printf("%s \n", argv[optind++]);
    }

    return 0;
}

struct baseline_state *baseline_init(int argc, char **argv) {
    printf("Running baseline with descriptors of size %lu\n",
           sizeof(struct descriptor));
    struct baseline_state *state = malloc(sizeof(struct baseline_state));
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
        printf("Error allocating memory for baseline_state\n");
        return NULL;
    }
    if (option_baseline(argc, argv, state) != 0) {
        printf("Error parsing command line arguments\n");
        return NULL;
    }
    printf("Allocating huge pool\n");
    #ifdef HAVE_MPRQ
        mbuf_pool =
        rte_pktmbuf_pool_create("MBUF_POOL", NUM_DEFAULT_MBUFS, MBUF_CACHE_SIZE, 0,
                                RTE_HUGE_MBUF_SIZE, rte_socket_id());
    #else
    mbuf_pool =
        rte_pktmbuf_pool_create("MBUF_POOL", NUM_DEFAULT_MBUFS, MBUF_CACHE_SIZE, 0,
                                RTE_MBUF_SIZE, rte_socket_id());
    #endif
    if (mbuf_pool == NULL) {
        printf("Error allocating mbuf pool\n");
        return NULL;
    }


    /* Initializing the desired port. */
    if (port_init(0, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
    printf("\nRunning on %d cores\n", rte_lcore_count());

    return state;
}

void baseline_run(void *state, int (*app)(void *)) {
    rte_eal_mp_remote_launch(app, state, SKIP_MAIN);
    rte_eal_mp_wait_lcore();
    /* clean up the EAL */
    rte_eal_cleanup();
}

void baseline_rx(struct baseline_state *state,
                 struct baseline_iterator *iterator) {
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


        if (nb_desc < 1 || nb_desc > 64) { // XXX Why this in baseline?
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
            rte_pktmbuf_free(bufs[i]); //XXX buffers could be re-used here directly
        }
    }
}

struct baseline_iterator *baseline_init_iterator(uint16_t burst_size) {
    struct baseline_iterator *iterator =
        calloc(1, sizeof(struct baseline_iterator));
    iterator->buf = calloc(burst_size, sizeof(struct rte_mbuf *));
    iterator->desc = calloc(burst_size, sizeof(struct descriptor *));
    iterator->nb_desc = calloc(burst_size, sizeof(uint8_t));
    return iterator;
}
struct descriptor *baseline_get_next(struct baseline_iterator *iterator) {
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

#include "rte_flow_utils.h"
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/if_ether.h>
#include <pthread.h>
#include <rte_arp.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_devargs.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_flow.h>
#include <rte_hash.h>
#include <rte_interrupts.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_random.h>
#include <rte_ring_core.h>
#include <rte_ring_elem.h>
#include <rte_spinlock.h>
#include <rte_string_fns.h>
#include <rte_tcp.h>
#include <rte_version.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#define MBUF_CACHE_SIZE 256
#define MBUF_DATA_SIZE (9800 + 256)
#define LARGE_MTU 9800
#define NUM_MBUFS 8192
#define RX_RING_SIZE 64
#define TX_RING_SIZE 64
#define MAC_BYTES 6 // Number of bytes in a MAC address

int receive_port;
int tcp_port;
SRC_OR_DST src_or_dst = Undefined;

struct arg_store {
    uint16_t nic_port;
    uint16_t tcp_port;
};
#define MAX_NUM_PORTS 64
int arg_store_index = 0;
struct arg_store arg_store[MAX_NUM_PORTS];

static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool,
                            int nb_rings, size_t MTU) {
    const uint16_t rx_rings = nb_rings, tx_rings = nb_rings;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    printf("port %d, rx_ring_size : %d, tx_ring_size : %d, nb_rings : %d\n",
           port, nb_rxd, nb_txd, rx_rings);
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

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
                .offloads = 0,
            },
    };
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

    retval = rte_eth_dev_set_mtu(port, MTU);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(
            port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    retval = rte_eth_dev_set_mtu(port, 9000);
    if (retval < 0) {
        printf("failed to set mtu\n");
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
    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           " %02" PRIx8 " %02" PRIx8 "\n",
           (unsigned int)port, addr.addr_bytes[0], addr.addr_bytes[1],
           addr.addr_bytes[2], addr.addr_bytes[3], addr.addr_bytes[4],
           addr.addr_bytes[5]);
    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;
    return 0;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

int find_port(struct rte_ether_addr addr) {
    int retval;
    struct rte_ether_addr tmp_addr;
    for (int i = 0; i < rte_eth_dev_count_avail(); i++) {
        retval = rte_eth_macaddr_get(i, &tmp_addr);
        if (retval != 0) {
            rte_exit(EXIT_FAILURE, "Cannot get MAC address of port %d\n", i);
            return -1;
        }
        if (memcmp(&addr, &tmp_addr, sizeof(struct rte_ether_addr)) == 0) {
            return i;
        }
    }
    rte_exit(EXIT_FAILURE, "Cannot find port with MAC address\n");
    return -1;
}

void mac_str_to_bytes(const char *mac_str, unsigned char *mac_bytes) {
    int values[MAC_BYTES];
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) == MAC_BYTES) {
        for (int i = 0; i < MAC_BYTES; i++) {
            mac_bytes[i] = (unsigned char)values[i];
        }
    }
}

void parse_destinations(char *str, struct arg_store *arg_store,
                        int arg_store_index) {
    const char delim = '|';   // Delimiter
    char *delimiter_position; // Pointer to the delimiter position
    delimiter_position = strchr(str, delim);
    if (delimiter_position != NULL) {
        // Replace the delimiter with null character to split the string
        *delimiter_position = '\0';

        // First part of the string
        char *first_part = str;
        struct rte_ether_addr addr;
        mac_str_to_bytes(first_part, addr.addr_bytes);
        arg_store[arg_store_index].nic_port = find_port(addr);
        // Second part of the string (starts after the delimiter)
        char *second_part = delimiter_position + 1;
        arg_store[arg_store_index].tcp_port = atoi(second_part);

    } else {
        printf("Delimiter not found in the string.\n");
    }
}

int rule_offloader_option(int argc, char **argv) {

    int c;
    int s = -1;

    while (1) {
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt(argc, argv, "s:d:");

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) {
        case 's':
            receive_port = atoi(optarg);
            break;
        case 'd':
            parse_destinations(optarg,arg_store,arg_store_index);
            break;
        case '?':
            /* getopt_long already printed an error message. */
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
int main(int argc, char *argv[]) {

    struct rte_flow_error error;
    struct rte_flow *flow;
    uint16_t portid;
    uint16_t lcore_id;
    int ret;
    struct rte_mempool *mbuf_pool;
    /* Initializion the Environment Abstraction Layer (EAL). 8< */
    printf("Initializing EAL\n");
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    /* >8 End of initialization the Environment Abstraction Layer (EAL). */

    argc -= ret;
    argv += ret;

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
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE,
                                        0, MBUF_DATA_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool : %d\n", rte_errno);
    }
    if (port_init(receive_port, mbuf_pool, 1, LARGE_MTU) != 0) {
        printf("Port initialization failed\n");
        return -1;
    }
    for (int i = 0; i < arg_store_index; i++) {
        uint16_t nic_port = arg_store[i].nic_port;
        uint16_t tcp_port = arg_store[i].tcp_port;

        if (port_init(nic_port, mbuf_pool, 1, LARGE_MTU) != 0) {
            printf("Port initialization failed\n");
            return -1;
        }
        flow = forward_traffic_to_representor(receive_port, nic_port, tcp_port,
                                              &error);
        if (!flow) {
            printf("Flow can't be created %d message: %s\n", error.type,
                   error.message ? error.message : "(no stated reason)");
            return -1;
        }
    }
    while (1) {
        sleep(5);
    }
    rte_eal_mp_wait_lcore();
    rte_eal_cleanup();

    return 0;
}



/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

// Simple proxy that listens to two ports and forwards packets from one port to
// another

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

#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256
#define RTE_TEST_RX_DESC_DEFAULT 2048
#define RTE_TEST_TX_DESC_DEFAULT 2048
#define NB_QUEUES 4
#define NB_MBUF 8192

#define MAX_PATTERN_NUM 10
#define MAX_ACTION_NUM 10

#define PORT_TO_WORLD 0
#define PORT_TO_HOST 1
#define PORTS_NEEDED 2

int ports_to_use[PORTS_NEEDED];

struct rte_mempool *mbuf_pools[2];
struct rte_flow *flows[2];

// statistics

static volatile bool force_quit;

static void init_port(int port_id, struct rte_mempool *mbuf_pool,
                      uint16_t nb_rx_queues, uint16_t nb_tx_queues) {
    int ret;
    static struct rte_eth_conf port_conf = (struct rte_eth_conf){
        .rxmode =
            {
                .mq_mode = RTE_ETH_MQ_RX_NONE,
            },
        .txmode =
            {
                .mq_mode = RTE_ETH_MQ_TX_NONE,
                .offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
                            RTE_ETH_TX_OFFLOAD_TCP_CKSUM,
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

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    }
    port_conf.txmode.offloads &= dev_info.tx_offload_capa;
    printf(":: initializing port: %d\n", port_id);
    ret =
        rte_eth_dev_configure(port_id, nb_rx_queues, nb_tx_queues, &port_conf);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, ":: cannot configure device: err=%d, port=%u\n",
                 ret, port_id);
    }

    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;
    /* >8 End of ethernet port configured with default settings. */

    /* Configuring number of RX and TX queues connected to single port. 8< */
    for (int i = 0; i < nb_rx_queues; i++) {
        ret = rte_eth_rx_queue_setup(port_id, i, RTE_TEST_RX_DESC_DEFAULT,
                                     rte_eth_dev_socket_id(port_id), &rxq_conf,
                                     mbuf_pool);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE,
                     ":: Rx queue setup failed: err=%d, port=%u\n", ret,
                     port_id);
        }
    }

    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.txmode.offloads;
    for (int i = 0; i < nb_tx_queues; i++) {
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

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

struct rte_flow *forward_traffic_to_port(uint16_t port_id,
                                         uint16_t forwarding_port,
                                         struct rte_flow_error *error) {
    /* Declaring structs being used. 8< */
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[MAX_PATTERN_NUM];
    struct rte_flow_action action[MAX_ACTION_NUM];
    struct rte_flow *flow = NULL;
    struct rte_flow_action_port_id port = {.id = forwarding_port};

    /* >8 End of declaring structs being used. */
    int res;

    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));

    /* Set the rule attribute, only ingress packets will be checked. 8< */
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.transfer = 1;
    /* >8 End of setting the rule attribute. */

    /*
     * create the action sequence.
     * one action only,  move packet to port
     */
    action[0].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
    action[0].conf = &port;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    /*
     * set the first level of the pattern (ETH).
     * since in this example we just want to get the
     * ipv4 we set this level to allow all.
     */

    /* Set this level to allow all. 8< */
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    /* >8 End of setting the first level of the pattern. */
    pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
    /* Validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    /* >8 End of validation the rule and create it. */
    return flow;
}

static int busy_loop(__rte_unused void *arg) {
    int count = 0;
    while (!force_quit) {
        count++;
    }

}
int main(int argc, char **argv) {
    unsigned lcore_id;
    int ret = 0;
    int portid;
    struct rte_flow_error error;
    struct rte_flow *flow;
    struct rte_flow_item_tcp tcp_spec;
    struct rte_flow_item_tcp tcp_mask;

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");
    argc -= ret;
    argv += ret;
    printf("EAL setup finshed\n");

    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    int nb_ports = rte_eth_dev_count_avail();
    printf("nb_ports: %d\n", nb_ports);
    char mbuf_pool_name[100] = "mbuf_pool_X";
    int nb_port_found = 0;
    struct rte_ether_addr port_mac;
    for (int portid = 0; portid < nb_ports; portid++) {
        struct rte_ether_addr addr = {0};
        rte_eth_macaddr_get(portid, &addr);
        uint8_t *mac_bytes = addr.addr_bytes;
        char macStr[100];
        snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3],
                 mac_bytes[4], mac_bytes[5]);
        printf("macStr : %s\n", macStr);

        mbuf_pool_name[strlen(mbuf_pool_name) - 1] = 48 + portid;
        mbuf_pools[portid] = rte_pktmbuf_pool_create(
            mbuf_pool_name, NB_MBUF * (NB_QUEUES + 1), MEMPOOL_CACHE_SIZE, 0,
            RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

        if (mbuf_pools[portid] == NULL)
            rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
    }
    init_port(PORT_TO_WORLD, mbuf_pools[PORT_TO_WORLD], NB_QUEUES, NB_QUEUES);
    init_port(PORT_TO_HOST, mbuf_pools[PORT_TO_HOST], NB_QUEUES, NB_QUEUES);

    flow = forward_traffic_to_port(PORT_TO_HOST, PORT_TO_WORLD, &error);
    if (!flow) {
        printf("Flow can't be created %d message: %s\n", error.type,
               error.message ? error.message : "(no stated reason)");
        return -1;
    }
    flow = forward_traffic_to_port(PORT_TO_WORLD, PORT_TO_HOST, &error);
    if (!flow) {
        printf("Flow can't be created %d message: %s\n", error.type,
               error.message ? error.message : "(no stated reason)");
        return -1;
    }
    printf("before create\n");

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_remote_launch(busy_loop, NULL, lcore_id);
    }
    while (!force_quit)
        sleep(1);
    /* clean up the EAL */
    rte_eal_cleanup();
    return 0;
}

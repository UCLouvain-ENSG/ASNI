
#include "test_utils.h"
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define MAX_PATTERN_NUM 10
#define MAX_ACTION_NUM 10
#define MAX_PKT_BURST 16
#define MEMPOOL_CACHE_SIZE 256
struct rte_mempool *mbuf_pool;
uint64_t nb_bytes_sent[128];
double time_elapsed[128];
static volatile bool force_quit = false;
int pkt_size = -1;
int ring_size = 1024;
int src_port = -1;
int dst_port = -1;
int flow_port_i = -1;
int flow_port_o = -1;
uint64_t nb_sucessfull_tx[128];
uint64_t batch_sizes_tx[128];
uint64_t nb_sucessfull_rx[128];
uint64_t batch_sizes_rx[128];
uint64_t square_batch_sizes_rx[128];
uint64_t nb_bytes_received[128];
uint64_t nb_received_packets[128];
char hostname[1024];
struct rte_eth_dev_tx_buffer *tx_buffer[32];

static int job(void *arg) {
    struct rte_mbuf *pkts[32];
    struct rte_mbuf *head;
    struct rte_mbuf *tail;
    uint16_t nb_tx;
    uint16_t nb_rx;
    uint64_t start = 0;
    int ret = 0;
    int mbuf_allocation_target = 8;
    int qid = rte_lcore_id() - 1;
    int rx_offset = 0;
    while (!force_quit) {
#ifdef CREATE_PACKETS
        do {
            ret =
                rte_pktmbuf_alloc_bulk(mbuf_pool, pkts, mbuf_allocation_target);
        } while ((ret != 0) && (!force_quit));
        if (force_quit) {
            break;
        }
        nb_rx = mbuf_allocation_target;
#else
        nb_rx = rte_eth_rx_burst(src_port, qid, pkts, mbuf_allocation_target);
#endif
        if (nb_rx == 0) {
            continue;
        }
        batch_sizes_rx[qid] += nb_rx;
        nb_sucessfull_rx[qid]++;
        if (!start) {
            printf("starting clock, qid : %d\n", qid);
            start = rte_get_tsc_cycles();
        }
        for (int i = 0; i < nb_rx; i++) {
            struct rte_ether_hdr *eth_hdr =
                rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
        }
#ifdef SG

#ifdef CREATE_PACKETS
        pkts[0]->data_len = pkt_size;
        pkts[0]->pkt_len = pkt_size;
#endif
        head = pkts[0];
        tail = pkts[0];
        for (int i = 1; i < nb_rx; i++) {

#ifdef CREATE_PACKETS
            pkts[i]->data_len = pkt_size;
            pkts[i]->pkt_len = pkt_size;
#endif
            tail->next = pkts[i];
            head->pkt_len += pkts[i]->pkt_len;
            head->nb_segs++;
            tail = pkts[i];
        }
        tail->next = NULL;
        uint16_t total_size = head->pkt_len;
#ifdef BUFFER
        nb_tx = rte_eth_tx_buffer(dst_port, qid, tx_buffer[qid], head);
        if (nb_tx != 0) {
            nb_sucessfull_tx[qid]++;
            batch_sizes_tx[qid] += nb_tx;
        }
#else
        nb_tx = rte_eth_tx_burst(dst_port, qid, &head, 1);
        if (unlikely(nb_tx != 1)) {
            rte_pktmbuf_free(head);
        } else {
            nb_sucessfull_tx[qid]++;
            batch_sizes_tx[qid] += nb_tx;
        }
#endif
#else
#ifdef CREATE_PACKETS
        for (int i = 0; i < nb_rx; i++) {
            pkts[i]->data_len = pkt_size;
            pkts[i]->pkt_len = pkt_size;
        }
#endif
        pkt_size = pkts[0]->pkt_len;
#ifdef FREE_INSTEAD_OF_SEND
        nb_tx = nb_rx;
        rte_pktmbuf_free_bulk(pkts, nb_tx);
#else
#ifdef SEND_ONE_BY_ONE
        for (int i = 0; i < nb_rx; i++) {
            nb_tx = rte_eth_tx_burst(dst_port, qid, &pkts[i], 1);
            if (unlikely(nb_tx != 1)) {
                rte_pktmbuf_free(pkts[i]);
            } else {
                nb_sucessfull_tx[qid]++;
                batch_sizes_tx[qid] += nb_tx;
            }
        }
#else
#ifdef SEND_LOOP
        uint16_t nb_packets_to_send = nb_rx;
        struct rte_mbuf **pkts_array = pkts;
        while (nb_packets_to_send > 0) {
            nb_tx =
                rte_eth_tx_burst(dst_port, qid, pkts_array, nb_packets_to_send);
            if (nb_tx > 0) {
                pkts_array += nb_tx;
                nb_packets_to_send -= nb_tx;
                nb_sucessfull_tx[qid]++;
                batch_sizes_tx[qid] += nb_tx;
            } else {
                rte_delay_us_block(50);
            }
        }
#elif defined(WAIT_FOR_RING)
        // rte_eth_tx_queue_count
        printf("inside wait for ring\n");
        int ret_count = rte_eth_tx_queue_count(dst_port, qid);
        while (ret_count < nb_rx) {
            if (ret_count < 0){ 
                printf("Error in tx queue count : %d\n",ret_count);
                return -1;
            }
        }
        nb_tx = rte_eth_tx_burst(dst_port, qid, pkts, nb_rx);

#else
        nb_tx = rte_eth_tx_burst(dst_port, qid, pkts, nb_rx);
        for (int i = nb_tx; i < nb_rx; i++) {
            rte_pktmbuf_free(pkts[i]);
        }
#endif
#endif
#endif
        nb_sucessfull_tx[qid]++;
        batch_sizes_tx[qid] += nb_tx;
#endif
    }
    uint64_t end = rte_get_tsc_cycles();
    time_elapsed[qid] = (double)(end - start) / rte_get_tsc_hz();
    return 0;
}

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM || signum == SIGKILL) {
        printf("\n\nSignal %d received, preparing to exit\n", signum);
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
int main(int argc, char *argv[]) {
    // args
    uint16_t lcore_id;
    int ret;
    int opt;
    struct rte_flow_error error;
    struct rte_flow *flow;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    /* Initializion the Environment Abstraction Layer (EAL). 8< */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    while ((opt = getopt(argc, argv, "l:s:d:i:o:r:")) != -1) {
        switch (opt) {
        case 'l':
            pkt_size = atoi(optarg);
            break;
        case 's':
            src_port = atoi(optarg);
            break;
        case 'd':
            dst_port = atoi(optarg);
            break;
        case 'i':
            flow_port_i = atoi(optarg);
            break;
        case 'o':
            flow_port_o = atoi(optarg);
            break;
        case 'r':
            ring_size = atoi(optarg);
            break;
        case '?':
            fprintf(stderr,
                    "Usage: %s -l <packet_size> -s <value> -d <value>\n",
                    argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // Check if required options are provided
#ifdef CREATE_PACKETS
    if (pkt_size == -1) {
        fprintf(stderr, "Please provide a packet size using the -l option.\n");
        exit(EXIT_FAILURE);
    }
#endif

    if (src_port == -1 || dst_port == -1) {
        fprintf(stderr, "Please provide values for both -s and -d options.\n");
        exit(EXIT_FAILURE);
    }

    // Your code logic with the values
    printf("Packet size set to: %d\n", pkt_size);
    printf("Src port set to: %d\n", src_port);
    printf("Dst port set to: %d\n", dst_port);
    /* >8 End of initialization the Environment Abstraction Layer (EAL). */
    /* Allocates mempool to hold the mbufs. 8< */
    uint16_t i;
    RTE_ETH_FOREACH_DEV(i) {
        char name[128] = "X_MBUF_POOL";
        name[0] = i;
        mbuf_pool = rte_pktmbuf_pool_create(
            name, (NUM_MBUFS * (rte_lcore_count() - 1) * 2) * 8,
            MBUF_CACHE_SIZE, 0, HUGE_MBUF_DATA_SIZE, rte_socket_id());

        if (mbuf_pool == NULL)
            rte_exit(EXIT_FAILURE, "Cannot create mbuf pool : %d\n", rte_errno);

        /* Initializing all ports. 8< */

        if (port_init(i, mbuf_pool, rte_lcore_count() - 1, ring_size) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", 0);
    }
    if (flow_port_i != -1 && flow_port_o != -1) {
        printf("Creating flow rule  port A : %d, port B : %d\n", flow_port_i,
               flow_port_o);
        flow = forward_traffic_to_port(flow_port_i, flow_port_o, &error);
        if (!flow) {
            printf("Flow can't be created %d message: %s\n", error.type,
                   error.message ? error.message : "(no stated reason)");
            return -1;
        }
    }
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
#ifdef BUFFER
        printf("lcore_id : %d\n", lcore_id);
        char name[128] = "X_TX_BUFFER";
        name[0] = lcore_id + 48;
        printf("name : %s\n", name);
        tx_buffer[lcore_id - 1] =
            rte_zmalloc_socket(name, RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
                               rte_eth_dev_socket_id(1));

        if (tx_buffer[lcore_id - 1] == NULL) {
            printf("Error during buffer allocation\n");
            return -1;
        }
        printf("RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST) : %d\n",
               RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST));

        printf("buffer : %p\n", tx_buffer[lcore_id - 1]);

        if (rte_eth_tx_buffer_init(tx_buffer[lcore_id - 1], MAX_PKT_BURST) !=
            0) {
            printf("Error during buffer init\n");
            return -1;
        }
#endif
        rte_eal_remote_launch(job, NULL, lcore_id);
    }
    rte_eal_mp_wait_lcore();

    double average_batch_size_tx = 0;
    double average_batch_size_rx = 0;
    for (int i = 0; i < rte_lcore_count() - 1; i++) {
        average_batch_size_tx +=
            (((double)batch_sizes_tx[i] / (double)nb_sucessfull_tx[i]));
        average_batch_size_rx +=
            (((double)batch_sizes_rx[i] / (double)nb_sucessfull_rx[i]));

        /* clean up the EAL */
    }
    uint16_t portid;
    double total_rx_throughput = 0;
    double total_tx_throughput = 0;
    double total_rx_pps = 0;
    double total_tx_pps = 0;
    RTE_ETH_FOREACH_DEV(portid) {
        struct rte_eth_stats stats;
        rte_eth_stats_get(portid, &stats);
        total_rx_throughput += (double)stats.ibytes;
        total_tx_throughput += (double)stats.obytes;
        total_rx_pps += (double)stats.ipackets;
        total_tx_pps += (double)stats.opackets;
    }
    hostname[1023] = '\0';
    gethostname(hostname, 1023);
    printf("Hostname: %s\n", hostname);
    printf("RESULT-TP-TX-%s %f\n", hostname,
           (double)(total_tx_throughput * 8) / (double)time_elapsed[0]);
    printf("RESULT-TP-RX-%s %f\n", hostname,
           (double)(total_rx_throughput * 8) / (double)time_elapsed[0]);
    printf("RESULT-PPS-TX-%s %f\n", hostname,
           (double)total_tx_pps / (double)time_elapsed[0]);
    printf("RESULT-PPS-RX-%s %f\n", hostname,
           (double)total_rx_pps / (double)time_elapsed[0]);
    printf("RESULT-AVERAGE-PKT-SIZE-%s %f\n", hostname,
           (double)total_rx_throughput / (double)total_rx_pps);

    printf("RESULT-BATCH-SIZE-TX-%s %f\n", hostname,
           average_batch_size_tx / (rte_lcore_count() - 1));

    printf("RESULT-BATCH-SIZE-RX-%s %f\n", hostname,
           average_batch_size_rx / (rte_lcore_count() - 1));
    rte_eal_cleanup();

    return 0;
}

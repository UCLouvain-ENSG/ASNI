#include "../../../utils/MACaddress.h"
#include "consts.h"
#include "descriptor_ipfill.h"
#include "generic/rte_byteorder.h"
#include "split.h"
#include <sys/types.h>
#include <unistd.h>
#ifdef DPT
#include "dma_setup.h"
#include <doca_argp.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_dev.h>
#include <doca_dma.h>
#endif
#include <doca_dpdk.h>
#include <doca_error.h>
#include <doca_log.h>
#include <getopt.h>
#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_flow_utils.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
DOCA_LOG_REGISTER(DMA_DPDK::MAIN);

int RX_RING_SIZE = 512;
int TX_RING_SIZE = 512;

#define RTE_MBUF_HUGE_SIZE 10000
#define NUM_MBUFS 2048
#define NUM_HUGE_MBUFS 2048
#define MBUF_CACHE_SIZE 256
#define NUM_PORTS 2
#define MAX_BURST_SIZE 256

#define SMALL_MTU 1500
#define LARGE_MTU 9800

#define MBUF_DATA_SIZE (2048 + 128)
#define MAX_NB_CORES 32
#define DMA_MAX_WINDOW 5

#ifdef DPT
#define PORT_TO_WORLD 1
#define PORT_TO_HOST 2
#else
#define PORT_TO_WORLD 0
#define PORT_TO_HOST 1
#endif

#define OTHER_PORT_TO_WORLD 2
#define OTHER_PORT_TO_HOST 3

#define PORT_TO_WORLD_TESTING 2

#define MAX_PKT_SIZE 9800
int WAITING_TIME = 10000;
#define debug(...)

int *rx_cores = NULL, *tx_cores = NULL;
int rx_size = 0, tx_size = 0;
static volatile bool force_quit = false;
static uint32_t nb_core = 1; /* The number of Core working (max 7) */
struct rte_mempool *mbuf_pool;
struct rte_mempool *mbuf_pools[32];
struct rte_mempool *header_mbuf;

int dpt = 0;
int _burst = 16;
int nopause = 0;
int RX_TARGET = 48;
char pcie_addr[128] = "0000:03:00.0";
struct rte_ether_addr macAddr1;
struct rte_ether_addr macAddr2;

struct arguments {
    uint16_t port_src;
    uint16_t port_dst;
    uint16_t qid;
    uint64_t nb_dropped;
};

bool payload_transfer_on = false;
bool direct_payload_transfer = false;

// attribute packed
struct arguments_dma {
    struct doca_pci_bdf *pcie_addr;
    uint16_t port;
    uint16_t lcore_index;
};

#ifdef DPT
struct rte_mempool *mbufs_pools[MAX_NB_CORES];
// A queue containing every job states on the fly
struct program_core_objects *flying_states[MAX_NB_CORES][DMA_MAX_WINDOW];
// A queue containing every job events on the fly
struct doca_event flying_events[MAX_NB_CORES][DMA_MAX_WINDOW];
// Reading head
uint8_t flying_head[MAX_NB_CORES] = {0};
// Current number of job on the fly
uint8_t flying_nb[MAX_NB_CORES] = {0};
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
size_t remote_addr_len[MAX_NB_CORES] = {0}, export_desc_len[MAX_NB_CORES] = {0};

uint64_t pos_payloads[MAX_NB_CORES] = {0};
char *ring_payloads[MAX_NB_CORES];
size_t size_payloads[MAX_NB_CORES];

#define MAX_DMA_BUF_SIZE                                                       \
    BURST_SIZE * sizeof(struct descriptor) /* DMA buffer maximum size          \
                                            */
#endif
static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM || signum == SIGKILL) {
        printf("\n\nSignal %d received, preparing to exit\n", signum);
        force_quit = true;
    }
}
/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int port_init_client(uint16_t port, struct rte_mempool *mbuf_pool,
                                   int nb_rings, size_t MTU) {
    const uint16_t rx_rings = nb_rings, tx_rings = nb_rings;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    printf("port_init_client client.c : port  %d, rx_ring_size : %d, "
           "tx_ring_size : "
           "%d, nb_rings : %d\n",
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
    port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
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
    printf("Before rx_queue_setup\n");
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

    if (nopause) {
        struct rte_eth_fc_conf fc_conf = {0};
        retval = rte_eth_dev_flow_ctrl_get(port, &fc_conf);

        fc_conf.mode = RTE_ETH_FC_NONE;
        retval = rte_eth_dev_flow_ctrl_set(port, &fc_conf);
        if (retval != 0)
            printf("Could not disable pause on %d\n", port);
    }
    return 0;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

static int job_split(void *arg) {
    printf("\ntx_core_id : %d\n", rte_lcore_id());
    void **full_arg = (void **)arg;
    struct arguments *args = (struct arguments *)(full_arg[0]);
    uint16_t port_src = args->port_src;
    uint16_t port_dst = args->port_dst;
    int id = args->qid;
    struct rte_mbuf *bufs[MAX_BURST_SIZE];
#ifndef DPT
    struct split_context *ctx = (struct split_context *)full_arg[1];
#endif
    struct rte_mbuf *pkts_burst_tx[MAX_BURST_SIZE];

    while (!force_quit) {
        const uint16_t nb_rx = rte_eth_rx_burst(port_src, id, bufs, _burst);
        if (nb_rx == 0)
            continue;
        for (int i = 0; i < nb_rx; i++) {
#ifdef DPT
            split_packet_dpt(bufs[i], port_dst, id, pkts_burst_tx);
#else
            split_packet_no_dpt(bufs[i], port_dst, id, ctx, pkts_burst_tx);
#endif
        }
    }
    return 0;
}

static int job(void *arg) {
    // args
    struct arguments *args = (struct arguments *)arg;
    uint16_t port_src = args->port_src;
    uint16_t port_dst = args->port_dst;
    int id = args->qid;
    uint8_t tag_id = 0;

#ifdef HAVE_CYCLE
    uint64_t start_cycle = 0;
    uint64_t end_cycle = 0;
    uint64_t total_usefull_cycles = 0;
    uint64_t tmp_start = 0;
    uint64_t tmp_end = 0;
    uint64_t pkt_processed = 0;
#endif
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    printf("port_src : %d\n", port_src);
    printf("port_dst : %d\n", port_dst);
    printf("id : %d\n", id);
    printf("BURST_SIZE : %d\n", _burst);
    printf("sizeof(struct descriptor) : %ld\n", sizeof(struct descriptor));
    printf("\nCore %u forwarding packets on queue %d. Header sz %d, num pos %d "
           "[Ctrl+C to quit]\n",
           rte_lcore_id(), id, offset_desc(), desc_pos());

    printf("TSC freq: %ld\n", rte_get_tsc_hz());
#ifdef WAIT_FOR_PACKETS
    struct rte_mbuf **bufs =
        rte_zmalloc("rx_bufs", RX_TARGET * sizeof(void *), 0);
    struct rte_mbuf **bufs_keeper = bufs;
    uint16_t nb_empty_rx = 0;
    uint16_t curr_nb_rx = 0;
    uint16_t nb_rx = 0;
#else
    struct rte_mbuf *bufs[MAX_BURST_SIZE];
#endif
    struct rte_mbuf *pkt;
    struct rte_mbuf *prev;
    int pkt_index = 0;

    for (;;) {
        uint16_t nb_tx;
        /* Quit the app on Control+C */
        if (force_quit) {
            if (rte_lcore_id() == 1) {
                // Get port stats
                struct rte_eth_stats new_stats;
                for (int j = 0; j < rte_eth_dev_count_avail(); j++) {
                    rte_eth_stats_get(j, &new_stats);
                    printf("=====================\n");
                    printf("PORT %d : \n", j);
                    // Print stats
                    printf("\nNumber of received packets : %ld"
                           "\nNumber of missed packets : %ld"
                           "\nNumber of queued RX packets : %ld"
                           "\nNumber of dropped queued packet : %ld\n\n",
                           new_stats.ipackets, new_stats.imissed,
                           new_stats.q_ipackets[0], new_stats.q_errors[0]);

                    printf("RESULT-NIC-DROPPED-ARM %lu\n", new_stats.imissed);
                    printf("RESULT-NIC-RECEIVED-ARM %lu\n", new_stats.ipackets);
                    if (new_stats.imissed != 0) {
                        printf("RESULT-RATIO-DROPPED-ARM %f\n",
                               (double)new_stats.imissed /
                                   ((double)new_stats.ipackets +
                                    (double)new_stats.imissed));
                    }
                    for (int i = 0; i < (rte_lcore_count() - 1); i++) {
                        printf("q_ipackets[%d] : %ld\n", i,
                               new_stats.q_ipackets[i]);
                    }
                    rte_eth_stats_get(j, &new_stats);
                    printf("RESULT-NIC-PKT-SENT %lu\n", new_stats.opackets);
                    printf("RESULT-NIC-PKT-TX-ERROR %lu\n", new_stats.oerrors);
                    printf("=====================\n");
                }
#ifdef HAVE_CYCLE
                printf("RESULT-CYCLES-PER-PACKET-NIC %lf\n",
                       (double)total_usefull_cycles / (double)pkt_processed);
#endif
            }
            return 0;
        }

        /* Get burst of RX packets. */
#ifdef HAVE_CYCLE
        tmp_start = rte_get_tsc_cycles();
#endif
#ifdef WAIT_FOR_PACKETS
        const uint16_t nb_rx_tmp = rte_eth_rx_burst(port_src, id, bufs, _burst);
        if (nb_rx_tmp == 0) {
            nb_empty_rx++;
            if (nb_empty_rx > WAITING_TIME && curr_nb_rx > 0) {
                nb_rx = curr_nb_rx;
                curr_nb_rx = 0;
                nb_empty_rx = 0;
                bufs = bufs_keeper;
            } else {
                continue;
            }
        } else {
            curr_nb_rx += nb_rx_tmp;
            if (!((curr_nb_rx + _burst) > RX_TARGET)) {
                bufs = (struct rte_mbuf **)(bufs + nb_rx_tmp);
                continue;
            } else {
                nb_rx = curr_nb_rx;
                bufs = bufs_keeper;
                curr_nb_rx = 0;
            }
        }
#else
        const uint16_t nb_rx = rte_eth_rx_burst(port_src, id, bufs, _burst);
#endif

        if (unlikely(nb_rx == 0))
            continue;
#ifdef HAVE_CYCLE
        tmp_end = rte_get_tsc_cycles();
        total_usefull_cycles += tmp_end - tmp_start;
        pkt_processed += (uint64_t)nb_rx;
#endif
        pkt_index = 0;
    start:
        /* Allocate the packet in the mbuf_pool */
        pkt = rte_pktmbuf_alloc(header_mbuf);
        if (pkt == NULL) {
            printf("Failed to allocate huge mbuf\n");
            return -1;
        }
        // Setup the number of desc in the payload
        uint8_t *data = rte_pktmbuf_mtod(pkt, uint8_t *);
        struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)data;
        // Used for rule steering when the packet comes back
        eth_hdr->src_addr.addr_bytes[0] = (uint8_t)(tag_id);
        // Magic to verify that the packet isn't corrupted/unwanted
        *(int *)(&eth_hdr->src_addr.addr_bytes[1]) = MAGIC;
        eth_hdr->ether_type = RTE_ETHER_TYPE_IPV4;
        tag_id = (tag_id + 1) % tx_size;
        // set the next field to the first packet
#ifdef DPT
        pkt->next = NULL;
#else
        pkt->next = bufs[pkt_index];
#endif
        pkt->data_len += DESC_OFFSET;
        pkt->pkt_len += DESC_OFFSET;
        prev = pkt;

        /* Modify the descriptor */
        for (; pkt_index < nb_rx; pkt_index++) {
            rte_prefetch0(bufs[pkt_index]);
            /* Link all the packets together */
            /* Packet is too big here */
#ifndef DPT
            if ((pkt->pkt_len + sizeof(struct descriptor) +
                 bufs[pkt_index]->pkt_len) > MAX_PKT_SIZE) {
                bufs[pkt_index - 1]->next = 0;

                *data = (pkt->nb_segs - 1);
                nb_tx = rte_eth_tx_burst(port_dst, id, &pkt, 1);

                if (unlikely(nb_tx != 1)) {
                    args->nb_dropped += nb_rx;
                    rte_pktmbuf_free(pkt);
                } else {
                    // printf("1 pkt_len : %d\n", pkt->pkt_len);
                    // printf("1 pkt_data : %d\n", pkt->data_len);
                    // printf("1 nb_seg : %d\n", pkt->nb_segs);
                }
                goto start;
            }
#endif
#ifndef DPT
            prev->next = bufs[pkt_index];
            pkt->nb_segs += 1;
#endif
#ifdef DP
            struct descriptor *desc = (struct descriptor *)rte_pktmbuf_prepend(
                bufs[pkt_index], sizeof(struct descriptor));
            rte_prefetch0(desc);
            asq_fill(bufs[pkt_index], desc);
            desc->size -= sizeof(struct descriptor);
#elif defined(PP)
            // We do nothing in the PP scenario

#else
            struct descriptor *desc =
                (struct descriptor *)(data + pkt->data_len);
            rte_prefetch0(desc);
            asq_fill(bufs[pkt_index], desc);
            pkt->data_len += sizeof(struct descriptor);
            pkt->pkt_len += sizeof(struct descriptor);
#endif
#ifndef DPT
            pkt->pkt_len += bufs[pkt_index]->pkt_len;
#else
            rte_pktmbuf_free(bufs[pkt_index]);
#endif
            prev = bufs[pkt_index];

            // We arrived at the last packet
        }
#ifndef DPT
        bufs[nb_rx - 1]->next = 0;
#endif
        /* Send burst of TX packets, to second port of pair. */
#ifdef DPT
        *data = nb_rx;
#else
        *data = (pkt->nb_segs - 1);
#endif
        nb_tx = rte_eth_tx_burst(port_dst, id, &pkt, 1);
        if (unlikely(nb_tx != 1)) {
            args->nb_dropped += nb_rx;
            rte_pktmbuf_free(pkt);
        }
        // printf("nb_tx : %d\n", nb_tx);
#ifdef HAVE_CYCLE
        tmp_end = rte_get_tsc_cycles();
        total_usefull_cycles += tmp_end - tmp_start;
        pkt_processed += (uint64_t)nb_rx;
#endif
    }
}

static int job_stat(void *arg) {
    // args
    uint16_t port_src = PORT_TO_WORLD;
    uint16_t port_dst = PORT_TO_HOST;
    uint64_t start_stats_cycles = 0;
    uint64_t end_stats_cycles = 0;
    uint64_t lasti = 0;
    uint64_t lasto = 0;
    double elapsed = 0;
    while (1) {
        /* Quit the app on Control+C */
        if (force_quit) {
            return 0;
        }
        // Get port stats
        struct rte_eth_stats src_stats;
        struct rte_eth_stats dst_stats;
        rte_eth_stats_get(port_src, &src_stats);
        rte_eth_stats_get(port_dst, &dst_stats);
        end_stats_cycles = rte_get_tsc_cycles();
        uint64_t total_received_packets = src_stats.ipackets;
        uint64_t total_missed_packets = src_stats.imissed;
        if (total_received_packets <= (1024 * 1024)) {
            continue;
        }
        if (start_stats_cycles == 0) {
            start_stats_cycles = end_stats_cycles;
        }
        printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
        printf("============RX-STATS===============\n");
        // RX_STATS
        if (start_stats_cycles != 0) {
            elapsed = (double)(end_stats_cycles - start_stats_cycles) /
                      rte_get_tsc_hz();
            printf("Elapsed time : %lf\n", elapsed);
        }
        printf("Number of received packets : %ld"
               "\nNumber of missed packets : %ld\n",
               total_received_packets, total_missed_packets);

        printf("RESULT-NIC-RECEIVED %lu\n", total_received_packets);
        uint64_t diffi = total_received_packets - lasti;

        printf("RESULT-NIC-PPS %lu\n", diffi);
        printf("RESULT-NIC-MPPS %lu\n", diffi / 1000000);
        if (elapsed != 0) {
            printf("RESULT-NIC-AVERAGE-MPPS %lf\n",
                   total_received_packets / elapsed / 1000000);
        }
        lasti = total_received_packets;
        printf("*************TX-STATS**************\n");
        // TX_STATS
        uint64_t total_sent_packets = dst_stats.opackets;
        uint64_t total_sent_errors = dst_stats.oerrors;
        uint64_t diffo = total_sent_packets - lasto;
        lasto = total_sent_packets;
        printf("Number of sent packets : %ld"
               "\nNumber of sent errors : %ld\n",
               total_sent_packets, total_sent_errors);
        printf("RESULT-NIC-PKT-SENT %lu\n", total_sent_packets);
        printf("RESULT-NIC-PKT-TX-ERROR %lu\n", total_sent_errors);
        printf("RSULT-NIC-PKT-SENT-AVG-MPPS %lf\n",
               (double)total_sent_packets / elapsed / 1000000);
        printf("RSULT-NIC-PKT-ERROR-AVG %lf\n",
               (double)total_sent_errors / elapsed);
        printf("------------ADVANCED-STATS----------\n");
        printf("RESULT-RATIO-RX/TX-(Estimated-actual-burst-size) %lf\n",
               (double)diffi / (double)diffo);
        printf("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
        // Sleep for 1 second
        sleep(1);
    }
}

void parse_cores(char *str, int **cores, int *size) {
    printf("Parsing cores : %s\n", str);
    char *token;
    int start, end;
    *cores = NULL;
    *size = 0;
    char *input = strdup(str); // Duplicate the string for safe modification

    token = strtok(input, ",");
    while (token) {
        if (strstr(token, "-")) {
            sscanf(token, "%d-%d", &start, &end);
            for (int i = start; i <= end; i++) {
                *cores = realloc(*cores, (*size + 1) * sizeof(int));
                (*cores)[*size] = i;
                (*size)++;
            }
        } else {
            *cores = realloc(*cores, (*size + 1) * sizeof(int));
            (*cores)[*size] = atoi(token);
            (*size)++;
        }
        token = strtok(NULL, ",");
    }
    printf("Parsed cores : ");
    for (int i = 0; i < *size; i++) {
        printf("%d ", (*cores)[i]);
    }
    free(input); // Free the duplicated string
}

int option(int argc, char **argv) {

    int c;

    while (1) {
        static struct option long_options[] = {
            /* These options set a flag. */
            {"burst", required_argument, 0, 'b'},
            {"disable-pause", no_argument, &nopause, 1},
            {"rx_cores", required_argument, 0, 0},
            {"tx_cores", required_argument, 0, 0},

        };
        /* getopt_long stores the option index here. */
        int option_index = 0;

        c = getopt_long(argc, argv, "c:s:b:w:t:r:p:l:", long_options,
                        &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) {
        case 0:
            /* If this option set a flag, do nothing else now. */
            if (strcmp(long_options[option_index].name, "rx_cores") == 0) {
                parse_cores(optarg, &rx_cores, &rx_size);
            } else if (strcmp(long_options[option_index].name, "tx_cores") ==
                       0) {
                parse_cores(optarg, &tx_cores, &tx_size);
            }
            if (long_options[option_index].flag != 0)
                break;
            break;
        case 'b':
            _burst = atoi(optarg);
            break;
        case 'c':
            nb_core = atoi(optarg);
            break;
        case 'w':
            WAITING_TIME = atoi(optarg);
            break;
        case 't':
            TX_RING_SIZE = atoi(optarg);
            break;
        case 'r':
            RX_RING_SIZE = atoi(optarg);
            break;
        case 'l':
            RX_TARGET = atoi(optarg);
            break;
        case 'p':
            strcpy(pcie_addr, optarg);
            break;
        case '?':
            /* getopt_long already printed an error message. */
            break;

        default:
            printf("Error: unknown argument %c/%s\n", c, optarg);
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

#define MAX_CORES 32

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[]) {
    // args
    struct arguments args[MAX_CORES] = {0};

    struct rte_flow_error error;
    struct rte_flow *flow;
    uint16_t lcore_id;
    int ret;
    bool offloaded_tx = false;

    // For some reasons here ports 2 and 3 should be used instead of 0 and 1
    /* Initializion the Environment Abstraction Layer (EAL). 8< */
    printf("Initializing EAL\n");
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    /* >8 End of initialization the Environment Abstraction Layer (EAL). */

    argc -= ret;
    argv += ret;

    ret = option(argc, argv);
    if (ret == -1)
        return -1;

    if (nopause) {
        printf("Pause frames disabled !\n");
    }

    #ifdef FAKE_DPDK_DESC_PAD
    printf("%d\n", FAKE_DPDK_DESC_PAD);
    #else
    printf("NO PADDDING SAAAAD\n");
    #endif
    printf("Size of used descriptors : %ld\n", sizeof(struct descriptor));

    offloaded_tx = rx_cores != NULL && tx_cores != NULL;
    int retval;

    printf("Available ports : \n");
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
    /* Allocates mempool to hold the mbufs. 8< */

    char mbuf_pool_name[128] = "0_MBUF_POOL";
    printf("mbuf_pool_name : %s\n", mbuf_pool_name);
#ifndef DPT
    mbuf_pool_name[0]++;
    mbuf_pools[PORT_TO_WORLD] = rte_pktmbuf_pool_create(
        mbuf_pool_name, NUM_MBUFS * nb_core, MBUF_CACHE_SIZE, 0,
        LARGE_MTU + 512, rte_socket_id());
    if (mbuf_pools[PORT_TO_WORLD] == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool : %s\n",
                 rte_strerror(rte_errno));
    }
#endif
    mbuf_pool_name[0]++;
    printf("mbuf_pool_name : %s\n", mbuf_pool_name);
    mbuf_pools[PORT_TO_HOST] = rte_pktmbuf_pool_create(
        mbuf_pool_name, NUM_MBUFS * nb_core, MBUF_CACHE_SIZE, 0,
        LARGE_MTU + 512, rte_socket_id());
    if (mbuf_pools[PORT_TO_HOST] == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool : %s\n",
                 rte_strerror(rte_errno));
    }
    int obj = sizeof(struct descriptor) * _burst + 128;
    header_mbuf = rte_pktmbuf_pool_create(
        "header_mbuf", NUM_MBUFS * nb_core, MBUF_CACHE_SIZE, 0,
        (obj>MBUF_DATA_SIZE + 512?obj:MBUF_DATA_SIZE + 512), rte_socket_id());
    if (header_mbuf == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create huge mbuf pool : %d (%s)\n",
                 rte_errno, rte_strerror(rte_errno));
    }
/* Initializing all ports. 8< */
#ifndef DPT
    if (tx_size == 0) {
        tx_size = nb_core;
    }
    if (port_init_client(PORT_TO_WORLD, mbuf_pools[PORT_TO_WORLD], tx_size,
                         SMALL_MTU) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", 0);
    }
    if (port_init_client(PORT_TO_HOST, mbuf_pools[PORT_TO_HOST], tx_size,
                         LARGE_MTU) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", 1);
    }

#else
    printf("Before dma_nic\n");
    ret = init_dma_nic(PORT_TO_WORLD, nb_core, pcie_addr);
    if (ret > 0) {
        printf("failed to init NIC\n");
        return -1;
    }
    portid = PORT_TO_HOST;
    if (port_init_client(portid, mbuf_pools[portid], nb_core, SMALL_MTU) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);

    printf("Ports after init_dma_nic: \n");
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
#endif
    printf("EVENT nic_ready\n");

    if (rte_lcore_count() > rte_lcore_count() - 1) {
        printf("\nWARNING: Too many lcores enabled, one must be kept for "
               "statistics.\n");
    }

    unsigned index = 0;

    if (!offloaded_tx) {
        printf("No TX offloading set\n");
        flow = forward_traffic_to_port(PORT_TO_HOST, PORT_TO_WORLD, &error);
        if (!flow) {
            printf("Flow can't be created %d message: %s\n", error.type,
                   error.message ? error.message : "(no stated reason)");
            return -1;
        }
        printf("Traffic forwarded from PORT %d to PORT %d\n", PORT_TO_HOST,
               PORT_TO_WORLD);
    } else {
        printf("TX offloading set\n");
        for (int i = 0; i < tx_size; i++) {
            flow = send_tag_to_queue(PORT_TO_HOST, i, i, &error);
            if (!flow) {
                printf("Flow can't be created %d message: %s\n", error.type,
                       error.message ? error.message : "(no stated reason)");
                return -1;
            }
        }
        flow = change_rss_hash(PORT_TO_WORLD, rx_size, &error);
        if (!flow) {
            printf("Flow can't be created %d message: %s\n", error.type,
                   error.message ? error.message : "(no stated reason)");
            return -1;
        }
        printf("TX offloading activated\n");
    }
    /* MAIN : polling each queue on a lcore */
    if (!offloaded_tx) {
        RTE_LCORE_FOREACH_WORKER(lcore_id) {
            args[index].port_src = PORT_TO_WORLD;
            args[index].port_dst = PORT_TO_HOST;
            args[index].qid = lcore_id - 1;

            if (lcore_id <= nb_core)
                rte_eal_remote_launch(job, &args[index], lcore_id);
            index++;
        }
    } else {
        printf("rx_cores : ");
        for (int i = 0; i < rx_size; i++) {
            printf("%d ", rx_cores[i]);
            args[index].port_src = PORT_TO_WORLD;
            args[index].port_dst = PORT_TO_HOST;
            args[index].qid = i;
            rte_eal_remote_launch(job, &args[index], rx_cores[i]);
            index++;
        }
        for (int i = 0; i < tx_size; i++) {
            printf("%d ", tx_cores[i]);
#ifndef DPT
            struct split_context *ctx = split_context_init(i);
            if (ctx == NULL) {
                printf("Failed to init split context\n");
                return -1;
            }
#endif
            void **wrapper = malloc(sizeof(void *) * 2);
            args[index].port_src = PORT_TO_HOST;
            args[index].port_dst = PORT_TO_WORLD;
            args[index].qid = i;
            wrapper[0] = &args[index];
#ifndef DPT
            wrapper[1] = ctx;
#endif
            printf("tx_cores[i] : %d\n", tx_cores[i]);
            rte_eal_remote_launch(job_split, wrapper, tx_cores[i]);
            index++;
        }
        printf("\n");
    }

    job_stat(&args);
    rte_eal_mp_wait_lcore();

    uint64_t total_dropped = 0;
    for (int i = 0; i < MAX_CORES; i++) {
        total_dropped += args[i].nb_dropped;
    }
    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}

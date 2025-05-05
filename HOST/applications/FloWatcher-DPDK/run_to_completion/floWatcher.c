#include <endian.h>
#define _GNU_SOURCE
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <pthread.h>
#include <sys/syscall.h>

#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_prefetch.h>
#include <rte_thash.h>
#include <rte_timer.h>

#include "asq_descriptors.h"
#include "dgu_utils.h"
#include "fake_dpdk.h"
#include "floWatcher.h"

#if defined(FAKE_DPDK_MODE_XCHG_ASNI) || defined(FAKE_DPDK_MODE_XCHG)
#include "main.h"
#endif

#define DOUBLE_HASH
#define IPG
#define FLOW_LEVEL
/* #define TIMESTAMP */
#define PORT_ID 0
#define RX_RINGS 1
#define NB_CORES 1
static uint64_t re[32];
#ifdef CRC_HEAVY_WORKLOAD
static uint64_t global = 0;
#endif
volatile bool force_quit;
#ifdef IP_WORKLOAD
uint64_t IP_COUNTER = 0;
#endif
#ifdef CRC_LIGHT_WORKLOAD
uint64_t CRC_COUNTER = 0;
#endif

#if defined(FAKE_DPDK_MODE_DPDK_ASQ_PP) ||                                     \
    defined(FAKE_DPDK_MODE_DPDK_ASQ_PP_EXP_DESC)
struct descriptor *descriptor;
#endif
static void signal_handler(int signum) {
#if defined(FAKE_DPDK_MODE_DPDK_ASQ_HW_DP) ||                                  \
    defined(FAKE_DPDK_MODE_DPDK_ASQ_HW_DD)
    printf("Not displaying extra stats");
#else
    // dgu_print_xstats();
#endif
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit\nPress again to "
               "force exit\n",
               signum);
        force_quit = true;
    }
}
#define RSS_HASH_KEY_LENGTH 40
static uint8_t hash_key[RSS_HASH_KEY_LENGTH] = {
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
};

static inline uint32_t software_hash(uint8_t *key, char *data,
                                     uint32_t data_len) {
    union rte_thash_tuple tuple = {0};
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)data;
    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    tuple.v4.src_addr = ipv4_hdr->src_addr;
    tuple.v4.dst_addr = ipv4_hdr->dst_addr;
    struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ipv4_hdr + 1);
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1);
    switch (ipv4_hdr->next_proto_id) {
    case IPPROTO_TCP:
        tuple.v4.dport = rte_be_to_cpu_16(tcp_hdr->dst_port);
        tuple.v4.sport = rte_be_to_cpu_16(tcp_hdr->src_port);
        break;
    case IPPROTO_UDP:
        tuple.v4.dport = rte_be_to_cpu_16(udp_hdr->dst_port);
        tuple.v4.sport = rte_be_to_cpu_16(udp_hdr->src_port);
        break;
    }
    // supports only ipv4
    int len = 12;
    return rte_softrss_be((uint32_t *)&tuple, len, hash_key);
}
#ifdef DOUBLE_HASH
static inline void app(struct fake_dpdk_state *fake_dpdk_state) {
#ifdef CRC_HEAVY_WORKLOAD
    uint32_t index_h, index_l;
#ifdef IPG
    int64_t curr;
#endif
#endif
#if defined(FAKE_DPDK_DESC_PAD) && (FAKE_DPDK_MODE_DPDK_BASELINE)
    unsigned pad_memset = getenv("PAD_MEMSET") != 0;
    printf("Padding %d\n", FAKE_DPDK_DESC_PAD);
    printf("Memset %d\n", pad_memset);
    printf("offset %d\n", dynfield_offset);
    if (dynfield_offset < 0)
        abort();

#endif

    unsigned lcore_id;
    lcore_id = rte_lcore_id();
    printf("Setting: core %u checks queue %d\n", lcore_id, lcore_id - 1);

    // associate to the number of rx queues.
    int q = lcore_id - 1;
    uint64_t bytes = 0;
    uint64_t start = 0;
    uint8_t start_flag = 0;

#ifdef FAKE_DPDK_MODE_DPDK_ASQ_PP
    descriptor = rte_malloc(NULL, sizeof(struct descriptor), 0);
#endif
    /* Run until the application is quit or killed. */
#ifdef IP_WORKLOAD
    printf("running additional IP workload\n");
#endif
#ifdef CRC_LIGHT_WORKLOAD
    printf("running light hash workload\n");
#endif
#ifdef CRC_HEAVY_WORKLOAD
    printf("running heavy hash workload\n");
#endif
#if !defined IP_WORKLOAD && !defined CRC_LIGHT_WORKLOAD &&                     \
    !defined CRC_HEAVY_WORKLOAD
    printf("running default workload\n");
#endif
    printf("EVENT server_ready\n");
    FAKE_DPDK_FOR_EACH_PACKET(descriptor);
    {
        if (unlikely(start_flag == 0)) {
            if (bytes > (1024 * 1024 * 1024)) {
                printf("received enough bytes : %ld\n", bytes);
                printf("Starting timer\n");
                start = rte_get_tsc_cycles();
                start_flag = 1;
                printf("start : %ld\n", start);
            }
        }
#if defined(FAKE_DPDK_DESC_PAD) && (FAKE_DPDK_MODE_DPDK_BASELINE)
        char* data = RTE_MBUF_DYNFIELD(descriptor, dynfield_offset, char *);
        if (FAKE_DPDK_DESC_PAD > 32) {
            rte_mempool_get (pad_pool, (void*)data);
            data = *(char**)data;
        }
        if (pad_memset)
            bzero(data, FAKE_DPDK_DESC_PAD);

#endif
        /* #ifdef IPG */
        /*         unsigned qNum = RX_RINGS; */
        /*         global = 0; */
        /*         while (qNum > 0) */
        /*             global += re[--qNum]; */
        /* #endif */
#ifdef IP_WORKLOAD
        struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)payload;
        struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
        IP_COUNTER += rte_be_to_cpu_32(ipv4_hdr->dst_addr);
#endif
#if (defined(CRC_LIGHT_WORKLOAD) || defined(CRC_HEAVY_WORKLOAD)) &&            \
    (defined(FAKE_DPDK_MODE_DPDK_ASQ_PP) ||                                    \
     defined(FAKE_DPDK_MODE_DPDK_ASQ_PP_EXP_DESC))
        descriptor->rss_hash =
            software_hash(hash_key, payload, descriptor->size);
#endif
        // #ifdef FAKE_DPDK_MODE_DPDK_BASELINE
        //         printf("size : %d\n", descriptor->pkt_len);
        // #else
        //         printf("size : %d\n", descriptor->size);
        // #endif
        re[q] += 1;
#if defined(FAKE_DPDK_MODE_DPDK_BASELINE)
        bytes += descriptor->pkt_len;
#elif defined(FAKE_DPDK_MODE_XCHG)
        bytes += descriptor->plen;
#else
        bytes += descriptor->size;
#endif
#ifdef CRC_LIGHT_WORKLOAD
#ifdef FAKE_DPDK_MODE_DPDK_BASELINE
        CRC_COUNTER += descriptor->hash.rss;
#else
        CRC_COUNTER += descriptor->rss_hash;
#endif
#endif
#ifdef CRC_HEAVY_WORKLOAD
#ifdef FLOW_LEVEL
        // Per packet processing
#ifdef FAKE_DPDK_MODE_DPDK_BASELINE

        index_l = descriptor->hash.rss & 0xffff;
        index_h = (descriptor->hash.rss & 0xffff0000) >> 16;
#else
        index_l = descriptor->rss_hash & 0xffff;
        index_h = (descriptor->rss_hash & 0xffff0000) >> 16;
#endif
#ifdef TIMESTAMP
        uint64_t timestamp = descriptor->timestamp;
        RTE_SET_USED(timestamp);
#endif
        if (pkt_ctr[index_l].hi_f1 == 0) {
            pkt_ctr[index_l].hi_f1 = index_h;
            pkt_ctr[index_l].ctr[0]++;

#ifdef IPG
            pkt_ctr[index_l].avg[0] = pkt_ctr[index_l].ipg[0];
#endif
        } else if (pkt_ctr[index_l].hi_f2 == 0 &&
                   pkt_ctr[index_l].hi_f1 != index_h) {
            pkt_ctr[index_l].hi_f2 = index_h;
            pkt_ctr[index_l].ctr[1]++;

#ifdef IPG
            pkt_ctr[index_l].avg[1] = pkt_ctr[index_l].ipg[1];
#endif
        } else {
            if (pkt_ctr[index_l].hi_f1 == index_h) {
                pkt_ctr[index_l].ctr[0]++;

#ifdef IPG
                curr = global - 1 - pkt_ctr[index_l].ipg[0];

                pkt_ctr[index_l].avg[0] =
                    (pkt_ctr[index_l].avg[0] * (pkt_ctr[index_l].ctr[0] - 1) +
                     curr) /
                    pkt_ctr[index_l].ctr[0];

                // if (pkt_ctr[index_l].ctr[0] < 10000 && index_l == 65246)
                //	printf("%lf %lu %ld\n", pkt_ctr[index_l].avg[0],
                // pkt_ctr[index_l].ctr[0], curr);

                pkt_ctr[index_l].ipg[0] = global;
#endif
            } else if (pkt_ctr[index_l].hi_f2 == index_h) {
                pkt_ctr[index_l].ctr[1]++;

#ifdef IPG
                curr = global - 1 - pkt_ctr[index_l].ipg[1];
                pkt_ctr[index_l].avg[1] =
                    ((pkt_ctr[index_l].avg[1] * (pkt_ctr[index_l].ctr[1] - 1)) +
                     curr) /
                    (float)pkt_ctr[index_l].ctr[1];

                pkt_ctr[index_l].ipg[1] = global;
#endif
            } else
                pkt_ctr[index_l].ctr[2]++;
        }
#endif
#endif

#if defined(FAKE_DPDK_DESC_PAD) && (FAKE_DPDK_MODE_DPDK_BASELINE)
        if (FAKE_DPDK_DESC_PAD > 32) {
            rte_mempool_put(pad_pool, data);
        }
#endif
    }
    FAKE_DPDK_FOR_EACH_PACKET_END();
#ifdef DOUBLE_HASH
    uint64_t sum = 0;
    int i = 0;
    for (i = 0; i < FLOW_NUM; i++) {
        // printf("Flow %d\n", i);
        sum += pkt_ctr[i].ctr[2];
    }
#elif defined(LINKED_LIST)

    struct flow_entry *f;

    uint64_t sum = 0, fls = 0;
    for (i = 0; i < FLOW_NUM; i++) {
        // printf("Flow entry %u: ", i);
        f = flows[i];

        while (f != NULL) {
            // printf("%u: %u  ", f->rss_high, f->ctr);
            sum += f->ctr;
            if (f->ctr)
                fls += 1;
            f = f->next;
        }

        // printf("\n");
    }

    printf("[Linked-list]: %lu flows with %lu packets\n", fls, sum);

#elif defined(HASH_LIST)

    flows = 0, sum = 0;
    struct flow_entry *f;

    for (i = 0; i < FLOW_NUM; i++) {
        //		printf("Flow entry %d: ", i);
        if (pkt_ctr[i].ctr[0] > 0) {
            flows += 1;
            sum += pkt_ctr[i].ctr[0];
        }

        if (pkt_ctr[i].ctr[1] > 0) {
            flows += 1;
            sum += pkt_ctr[i].ctr[1];
        }

        //		printf("%u: %u  %u: %u  ", pkt_ctr[i].hi_f1,
        // pkt_ctr[i].ctr[0], pkt_ctr[i].hi_f2, pkt_ctr[i].ctr[1]);
        f = pkt_ctr[i].flows;
        while (f != NULL) {
            if (f->ctr > 0)
                flows += 1;
            sum += f->ctr;
            // printf("%u: %u  ", f->rss_high, f->ctr);
            f = f->next;
        }
        //		printf("\n");
    }

    printf("[Double Hash + Linked-list]: %lu flows with %lu packets\n", flows,
           sum);
#endif

    struct rte_eth_stats eth_stats;
    rte_eth_stats_get(PORT_ID, &eth_stats);
    printf("\nDPDK: Received pkts %lu \nDropped packets %lu \nErroneous "
           "packets %lu\n",
           eth_stats.ipackets + eth_stats.imissed + eth_stats.ierrors,
           eth_stats.imissed, eth_stats.ierrors);
    double end = rte_get_tsc_cycles();
    double time_elapsed = (double)(end - start) / rte_get_tsc_hz();
    printf("end : %lf\n", end);
    printf("time elapsed : %lf\n", time_elapsed);
    double real_tp = ((bytes * 8) / time_elapsed) / 1000000000;
    printf("RESULT-Throughput %fGbps\n", real_tp);
    printf("\nQueue %d counter's value: %lu\n", q, re[q]);

    double mpps = (double)(re[q] / time_elapsed) / 1000000;
    printf("RESULT-Throughput-L1 %fGbps\n",
           (double)((real_tp) + (24 * mpps) / 1000));
    printf("RESULT-MPPS %f\n", mpps);
    printf("\nThe total number of miscounted packets is %lu\n", sum);
#ifdef IP_WORKLOAD
    printf("The total number of IP addresses is %lu\n", IP_COUNTER);
#endif
#ifdef CRC_LIGHT_WORKLOAD
    printf("The total number of CRC values is %lu\n", CRC_COUNTER);
#endif

    dgu_print_xstats();
}
#endif

int main(int argc, char const *argv[]) {
    // Setup
    // in/etinfo/users2/tyunyayev/Workspace/ASNI/measurements/flowatcher-Throughput.pditerrupts
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    printf("sizeof(struct descriptor) : %ld\n", sizeof(struct descriptor));
    printf("Starting floWatcher\n");
    fake_dpdk_init(argc, (char **)argv, NB_CORES, BURST_SIZE,
                   (int (*)(void *))app, &force_quit);
    printf("Exiting floWatcher\n");
    return 0;
}

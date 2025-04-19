#include "rte_ip.h"
#include "test_utils.h"
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct rte_mempool *huge_mbuf_pool;
uint64_t nb_bytes = 0;
uint64_t start = 0;
uint64_t end = 0;
static volatile bool force_quit = false;

static int job(void *arg) {
    struct rte_mbuf *bufs[32];
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    uint16_t nb_rx;
    uint8_t octets[4];
    printf("inside job\n");
    while (!force_quit) {
        nb_rx = rte_eth_rx_burst(0, 0, bufs, 32);
        if (nb_rx == 0) {
            continue;
        }
        if (start == 0) {
            printf("starting clock\n");
            start = rte_get_tsc_cycles();
        }
        for (int i = 0; i < nb_rx; i++) {
#ifdef PKT_INFO
            eth_hdr = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
            ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
            printf("pkt_len : %d\n", bufs[i]->pkt_len);
            printf("data_len : %d\n", bufs[i]->data_len);
            printf("data_len : %d\n", bufs[i]->data_len);
            uint32_t ipv4_src = htonl(ipv4_hdr->dst_addr);
            octets[0] = (ipv4_src >> 24) & 0xFF;
            octets[1] = (ipv4_src >> 16) & 0xFF;
            octets[2] = (ipv4_src >> 8) & 0xFF;
            octets[3] = ipv4_src & 0xFF;
            printf("IPv4 address: %d.%d.%d.%d\n", octets[0], octets[1],
                   octets[2], octets[3]);
#endif
#ifdef TP_INFO
            nb_bytes += bufs[i]->pkt_len;
#endif
        }
        rte_pktmbuf_free_bulk(bufs, nb_rx);
    }
    return 0;
}

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM || signum == SIGKILL) {
        printf("\n\nSignal %d received, preparing to exit\n", signum);

        static const char *stats_border = "_______";
        uint16_t portid;
        RTE_ETH_FOREACH_DEV(portid) {

            struct rte_eth_xstat *xstats;
            struct rte_eth_xstat_name *xstats_names;
            int len, ret, i;

            printf("PORT STATISTICS:\n================\n");
            len = rte_eth_xstats_get(portid, NULL, 0);
            if (len < 0)
                rte_exit(EXIT_FAILURE, "rte_eth_xstats_get(%u) failed: %d",
                         portid, len);
            xstats = calloc(len, sizeof(*xstats));
            if (xstats == NULL)
                rte_exit(EXIT_FAILURE, "Failed to calloc memory for xstats");
            ret = rte_eth_xstats_get(portid, xstats, len);
            if (ret < 0 || ret > len) {
                free(xstats);
                rte_exit(EXIT_FAILURE,
                         "rte_eth_xstats_get(%u) len%i failed: %d", portid, len,
                         ret);
            }
            xstats_names = calloc(len, sizeof(*xstats_names));
            if (xstats_names == NULL) {
                free(xstats);
                rte_exit(EXIT_FAILURE,
                         "Failed to calloc memory for xstats_names");
            }
            ret = rte_eth_xstats_get_names(portid, xstats_names, len);
            if (ret < 0 || ret > len) {
                free(xstats);
                free(xstats_names);
                rte_exit(EXIT_FAILURE,
                         "rte_eth_xstats_get_names(%u) len%i failed: %d",
                         portid, len, ret);
            }
            for (i = 0; i < len; i++) {
                if (xstats[i].value > 0)
                    printf("Port %u: %s %s:\t\t%" PRIu64 "\n", portid,
                           stats_border, xstats_names[i].name, xstats[i].value);
            }

            struct rte_eth_stats stats;
            rte_eth_stats_get(portid, &stats);
            // // Print stats
            printf("\n\n===basic stats port %d : ===\n\n", portid);
            printf("\nTotal number of successfully received packets : %ld"
                   "\nTotal of Rx packets dropped by the HW, because there are "
                   "no available buffer : % ld "
                   "\nTotal number of failed transmitted packets : %ld"
                   "\nTotal number of successfully transmitted packets : % ld ",
                   stats.ipackets, stats.imissed, stats.oerrors,
                   stats.opackets);
            printf("\n\n=============================\n\n");
        }

        end = rte_get_tsc_cycles();
        double time_elapsed = (double)(end - start) / rte_get_tsc_hz();
        printf("nb_bytes : %lu\n", nb_bytes);
        printf("RESULT-TESTTIME %f\n", time_elapsed);
        printf("RESULT-THROUGHPUT %fGbps\n",
               ((double)((nb_bytes) * 8) / time_elapsed) / 1000000000.0);
        // Get port stats

        force_quit = true;
    }
}
int main(int argc, char *argv[]) {
    // args
    uint16_t portid;
    uint16_t lcore_id;
    int ret;
    /* Initializion the Environment Abstraction Layer (EAL). 8< */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    /* >8 End of initialization the Environment Abstraction Layer (EAL). */
    /* Allocates mempool to hold the mbufs. 8< */
    huge_mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_MBUFS * (rte_lcore_count() - 1) * 2, MBUF_CACHE_SIZE,
        0, HUGE_MBUF_DATA_SIZE, rte_socket_id());

    if (huge_mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool : %d\n", rte_errno);

    /* Initializing all ports. 8< */
    printf("before port init\n");
    if (port_init(0, huge_mbuf_pool, rte_lcore_count() - 1) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", 0);
    printf("after port init\n");

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_remote_launch(job, NULL, lcore_id);
    }
    rte_eal_mp_wait_lcore();

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}

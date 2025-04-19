#include "dgu_utils.h"
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
void dgu_print_xstats() {
    printf("before RTE_ETH_FOREACH_DEV\n");
#ifndef FAKE_DPDK_MODE_DMA
    static const char *stats_border = "_______";
    uint16_t portid;
    RTE_ETH_FOREACH_DEV(portid) {
        printf("inside RTE_ETH_FOREACH_DEV\n");
        struct rte_eth_xstat *xstats;
        struct rte_eth_xstat_name *xstats_names;
        int len, ret, i;
        printf("PORT STATISTICS:\n================\n");
        len = rte_eth_xstats_get(portid, NULL, 0);
        if (len < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_xstats_get(%u) failed: %d", portid,
                     len);
        xstats = calloc(len, sizeof(*xstats));
        if (xstats == NULL)
            rte_exit(EXIT_FAILURE, "Failed to calloc memory for xstats");
        ret = rte_eth_xstats_get(portid, xstats, len);
        if (ret < 0 || ret > len) {
            free(xstats);
            rte_exit(EXIT_FAILURE, "rte_eth_xstats_get(%u) len%i failed: %d",
                     portid, len, ret);
        }
        xstats_names = calloc(len, sizeof(*xstats_names));
        if (xstats_names == NULL) {
            free(xstats);
            rte_exit(EXIT_FAILURE, "Failed to calloc memory for xstats_names");
        }
        ret = rte_eth_xstats_get_names(portid, xstats_names, len);
        if (ret < 0 || ret > len) {
            free(xstats);
            free(xstats_names);
            rte_exit(EXIT_FAILURE,
                     "rte_eth_xstats_get_names(%u) len%i failed: %d", portid,
                     len, ret);
        }
        for (i = 0; i < len; i++) {
            if (xstats[i].value > 0)
                printf("Port %u: %s %s:\t\t%" PRIu64 "\n", portid, stats_border,
                       xstats_names[i].name, xstats[i].value);
        }

        struct rte_eth_stats stats;
        rte_eth_stats_get(portid, &stats);
        // // Print stats
        printf("\n\n===basic stats port %d : ===\n\n", portid);
        printf("\nTotal number of successfully received packets : %ld"
               "\nTotal of Rx packets dropped by the HW, because there are "
               "no available buffer : %ld"
               "\nTotal number of failed transmitted packets : %ld"
               "\nTotal number of successfully transmitted packets : %ld",
               stats.ipackets, stats.imissed, stats.oerrors, stats.opackets);
        printf("\n\n=============================\n\n");
    }
#endif
}

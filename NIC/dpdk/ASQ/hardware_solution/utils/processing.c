/*Necessary for DD version 32 is too big packets are not send*/
#include "rte_malloc.h"
#include <rte_mbuf_core.h>
#include <stdint.h>
#include <stdio.h>
#define PACKET_BURST_DP 16
#define PACKET_BURST_DD 16
#include "asq_descriptors.h"
#include "consts.h"
#include "structs_enums.h"
#include <doca_flow.h>
#include <doca_log.h>
#include <my_structs.h>
#include <rte_ethdev.h>
#include <rte_memcpy.h>
#include <string.h>
#include <unistd.h>
#define DEBUG 1
void scatter_gather_packets(int in_port, int out_port, int qid,
                            volatile bool *fq, struct rte_mempool *mp,
                            enum SG_TYPE sg_type, struct my_stats *stats) {

    struct rte_mbuf *prev;
    struct rte_mbuf *curr;

    struct rte_mbuf *prev_desc;
    struct rte_mbuf *curr_desc;

    struct rte_mbuf *prev_payl;
    struct rte_mbuf *curr_payl;

    int nb_rx;
    int nb_tx;
    struct rte_mbuf *head;
    struct rte_mbuf *head_desc;
    const int ENCAP_SIZE = sizeof(struct descriptor);

#ifdef HAVE_CYCLE
    uint64_t start_cycle = 0;
    uint64_t end_cycle = 0;
    uint64_t total_usefull_cycles = 0;
    uint64_t tmp_start = 0;
    uint64_t tmp_end = 0;
    uint64_t pkt_processed = 0;
    uint64_t successful_rx = 0;
#endif

    struct rte_mbuf *head_payl;
    struct rte_mbuf *pkt;
    struct rte_ether_addr addr;
    int retval = rte_eth_macaddr_get(in_port, &addr);
    if (retval != 0)
        printf("failed to get mac_addr\n");
    printf("Port_in %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           " %02" PRIx8 " %02" PRIx8 "\n",
           (unsigned int)in_port, addr.addr_bytes[0], addr.addr_bytes[1],
           addr.addr_bytes[2], addr.addr_bytes[3], addr.addr_bytes[4],
           addr.addr_bytes[5]);

    retval = rte_eth_macaddr_get(out_port, &addr);
    if (retval != 0)
        printf("failed to get mac_addr\n");
    printf("Port_out %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           " %02" PRIx8 " %02" PRIx8 "\n",
           (unsigned int)out_port, addr.addr_bytes[0], addr.addr_bytes[1],
           addr.addr_bytes[2], addr.addr_bytes[3], addr.addr_bytes[4],
           addr.addr_bytes[5]);
    int ACTUAL_RX_BURST;
    if (sg_type == DP) {
        printf("Running DP mode\n");
        ACTUAL_RX_BURST = PACKET_BURST_DP;
    } else if (sg_type == DD) {
        printf("Running DD mode\n");
        ACTUAL_RX_BURST = PACKET_BURST_DD;
    } else {
        printf("Unsupported sg mode\n");
        return;
    }
    struct rte_mbuf *packets[PACKET_BURST_DP];
    while (!(*fq)) {

#ifdef HAVE_CYCLE
        tmp_start = rte_get_tsc_cycles();
#endif
        nb_rx = rte_eth_rx_burst(in_port, qid, packets, ACTUAL_RX_BURST);
        if (!nb_rx) {
            // printf("rx_failed \n");
            continue;
        }
        // for (int i = 0; i < nb_rx; i++) {
        //     struct rte_mbuf *pkt = packets[i];
        //     printf("pkt->pkt_len : %d\n", pkt->pkt_len);
        // }
#ifdef HAVE_CYCLE
        if (start_cycle == 0) {
            start_cycle = rte_get_tsc_cycles();
        }
        successful_rx++;
#endif
        pkt = rte_pktmbuf_alloc(mp);
        if (pkt == NULL) {
            // printf("Fail to allocate buffer for nb_descriptor\n");
            rte_pktmbuf_free_bulk(packets, nb_rx);
            continue;
        }

        uint8_t *data = rte_pktmbuf_mtod(pkt, uint8_t *);
        *(data) = (uint8_t)nb_rx;

        struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)data;
        *(int *)(&eth_hdr->src_addr.addr_bytes[1]) = MAGIC;
        pkt->pkt_len = DESC_OFFSET;
        pkt->data_len = DESC_OFFSET;
        if (sg_type == DP) {
            head = packets[0];
            struct descriptor *desc =
                rte_pktmbuf_mtod(head, struct descriptor *);
            struct rte_ether_hdr *eth_hdr =
                rte_pktmbuf_mtod(head, struct rte_ether_hdr *);
            // printing mac_address
            // printf("mac_src : %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02"
            // PRIx8
            //        " %02" PRIx8 " %02" PRIx8 "\n",
            //        eth_hdr->src_addr.addr_bytes[0],
            //        eth_hdr->src_addr.addr_bytes[1],
            //        eth_hdr->src_addr.addr_bytes[2],
            //        eth_hdr->src_addr.addr_bytes[3],
            //        eth_hdr->src_addr.addr_bytes[4],
            //        eth_hdr->src_addr.addr_bytes[5]);
            // printf("dst_src : %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02"
            // PRIx8
            //        " %02" PRIx8 " %02" PRIx8 "\n",
            //        eth_hdr->dst_addr.addr_bytes[0],
            //        eth_hdr->dst_addr.addr_bytes[1],
            //        eth_hdr->dst_addr.addr_bytes[2],
            //        eth_hdr->dst_addr.addr_bytes[3],
            //        eth_hdr->dst_addr.addr_bytes[4],
            //        eth_hdr->dst_addr.addr_bytes[5]);

            // printf("size : %u\n", (unsigned int)desc->size);
            // printf("direct_size : %u\n", (unsigned int)(*(uint16_t *)desc));
            // printf("htons_size : %u\n", (unsigned int)htons(desc->size));
            // printf("pkt_len : %u\n", (unsigned int)head->pkt_len);
            head->pkt_len = head->data_len;
            prev = head;

#ifdef SOFT_REORDERING
            int pkt_offset = DESC_OFFSET;

            prev->pkt_len -= ENCAP_SIZE;
            prev->data_len -= ENCAP_SIZE;

            rte_memcpy(rte_pktmbuf_mtod(pkt, uint8_t *) + pkt_offset,
                       rte_pktmbuf_mtod(prev, uint8_t *), ENCAP_SIZE);
            prev->data_off += ENCAP_SIZE;

            pkt_offset += ENCAP_SIZE;
            pkt->pkt_len += ENCAP_SIZE;
            pkt->data_len += ENCAP_SIZE;
#endif
            for (int i = 1; i < nb_rx; i++) {
                rte_prefetch0(packets[i]);
                curr = packets[i];
#ifndef SOFT_REORDERING
                prev->next = curr;
                head->nb_segs++;
                head->pkt_len += curr->pkt_len;
                curr->pkt_len = curr->data_len;
#else
                prev->next = curr;
                head->nb_segs++;
                head->pkt_len += (curr->pkt_len - ENCAP_SIZE);
                curr->pkt_len -= ENCAP_SIZE;
                curr->data_len -= ENCAP_SIZE;
                rte_memcpy(rte_pktmbuf_mtod(pkt, uint8_t *) + pkt_offset,
                           rte_pktmbuf_mtod(curr, uint8_t *), ENCAP_SIZE);
                curr->data_off += ENCAP_SIZE;
                pkt_offset += ENCAP_SIZE;
                pkt->pkt_len += ENCAP_SIZE;
                pkt->data_len += ENCAP_SIZE;
#endif
                prev = curr;
            }
            if (rte_pktmbuf_chain(pkt, head) < 0) {
                printf("failed to chain mbufs\n");
            }
            nb_tx = rte_eth_tx_burst(out_port, qid, &pkt, 1);
            if (unlikely(nb_tx != 1)) {
                rte_pktmbuf_free(pkt);
            } else {
                stats->nb_packets_send += nb_rx;
            }
#ifdef HAVE_CYCLE

            tmp_end = rte_get_tsc_cycles();
            total_usefull_cycles += tmp_end - tmp_start;
            pkt_processed += (uint64_t)nb_rx;
#endif
        } else if (sg_type == DD) {
            /* printf("inside DD\n"); */

            head_desc = packets[0];
            head_payl = packets[0]->next;

            /*should never happen because packets are processed in doca_flow*/

            head_desc->pkt_len = head_desc->data_len;
            head_payl->pkt_len = head_payl->data_len;

            head_desc->nb_segs = 1;
            head_payl->nb_segs = 1;

            prev_desc = head_desc;
            prev_payl = head_payl;
            for (int i = 1; i < nb_rx; i++) {
                curr_desc = packets[i];
                curr_desc->nb_segs = 1;
                curr_payl = packets[i]->next;

                prev_desc->next = curr_desc;
                prev_payl->next = curr_payl;

                head_desc->nb_segs++;
                head_payl->nb_segs++;

                head_desc->pkt_len += curr_desc->data_len;
                curr_desc->pkt_len = curr_desc->data_len;

                head_payl->pkt_len += curr_payl->data_len;
                curr_payl->pkt_len = curr_payl->data_len;

                prev_desc = curr_desc;
                prev_payl = curr_payl;
            }
            prev_desc->next = head_payl;
            prev_payl->next = NULL;
            head_desc->nb_segs += head_payl->nb_segs;
            head_payl->nb_segs = 1;
            head_desc->pkt_len += head_payl->pkt_len;
            head_payl->pkt_len = head_payl->data_len;
            if (rte_pktmbuf_chain(pkt, head_desc) < 0) {
                printf("failed to chain mbufs\n");
            }
            nb_tx = rte_eth_tx_burst(out_port, qid, &pkt, 1);
            if (unlikely(nb_tx != 1)) {
                rte_pktmbuf_free(pkt);
            }
#ifdef HAVE_CYCLE

            tmp_end = rte_get_tsc_cycles();
            total_usefull_cycles += tmp_end - tmp_start;
            pkt_processed += nb_rx;
#endif
        } else {
            printf("SG_TYPE not supported");
            return;
        }
    }
#ifdef HAVE_CYCLE
    printf("total_usefull_cycles : %ld\n", total_usefull_cycles);
    printf("pkt_processed : %ld\n", pkt_processed);
    printf("RESULT-CYCLES-PER-PACKET-NIC %lf\n",
           (double)total_usefull_cycles / (double)pkt_processed);
    printf("RESULT-AVERAGE-BURST-SIZE-NIC %lf\n",
           (double)pkt_processed / (double)successful_rx);
#endif
}

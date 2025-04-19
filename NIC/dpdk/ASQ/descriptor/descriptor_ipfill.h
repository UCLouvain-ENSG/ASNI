#include "asq_descriptors.h"
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <stdint.h>

static int offset_desc() { return 16; }

static int desc_pos() { return 0; }

struct __attribute__((packed)) transport_ports {
    uint16_t src;
    uint16_t dst;
};

void asq_fill(struct rte_mbuf *pkt, struct descriptor *desc) {

#ifdef FAKE_DPDK_DESC_SIZE
    desc->size = pkt->data_len;
#endif
#if defined(FAKE_DPDK_DESC_MAC_SRC) || defined(FAKE_DPDK_DESC_MAC_DST) ||      \
    defined(FAKE_DPDK_DESC_ETH_TYPE)
#define PAYLOAD_PTR_EXISTS 1
    uint8_t *payload = rte_pktmbuf_mtod(pkt, uint8_t *);
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)payload;
#ifdef FAKE_DPDK_DESC_ETH_TYPE
    desc->eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);
#endif
    for (int i = 0; i < 6; i++) {
#ifdef FAKE_DPDK_DESC_MAC_SRC
        desc->mac_src[i] = eth_hdr->src_addr.addr_bytes[i];
#endif
#ifdef FAKE_DPDK_DESC_MAC_DST
        desc->mac_dst[i] = eth_hdr->dst_addr.addr_bytes[i];
#endif
    }
#endif
#if defined(FAKE_DPDK_DESC_IP_SRC) || defined(FAKE_DPDK_DESC_IP_DST) ||        \
    defined(FAKE_DPDK_IP_PROTO)
    if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
        struct rte_ipv4_hdr *ip_hdr;
#ifdef PAYLOAD_PTR_EXISTS
        ip_hdr =
            (struct rte_ipv4_hdr *)(payload + sizeof(struct rte_ether_hdr));
#else
#define PAYLOAD_PTR_EXISTS 1
        ip_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *,
                                         sizeof(struct rte_ether_hdr));
#endif
#ifdef FAKE_DPDK_DESC_IP_SRC
        desc->ip_src = rte_be_to_cpu_32(ip_hdr->src_addr);
#endif
#ifdef FAKE_DPDK_DESC_IP_DST
        desc->ip_dst = rte_be_to_cpu_32(ip_hdr->dst_addr);
#endif
#ifdef FAKE_DPDK_DESC_IP_PROTO
        desc->ip_proto = ip_hdr->next_proto_id;
#endif
    } else {
        printf("\nCore %d,IP header doesn't match IPV4 type\n", rte_lcore_id());
    }
#endif
#if defined(FAKE_DPDK_DESC_PORT_SRC) || defined(FAKE_DPDK_DESC_PORT_DST)
    if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
        struct transport_ports *ports;
#ifdef PAYLOAD_PTR_EXISTS
        ports =
            (struct transport_ports *)(payload + sizeof(struct rte_ether_hdr) +
                                       sizeof(struct rte_ipv4_hdr));
#else
#define PAYLOAD_PTR_EXISTS 1
        ports = rte_pktmbuf_mtod_offset(pkt, struct transport_ports *,
                                        sizeof(struct rte_ether_hdr) +
                                            sizeof(struct rte_ipv4_hdr));
#endif
#ifdef FAKE_DPDK_DESC_PORT_SRC
        desc->port_src = rte_be_to_cpu_16(ports->src);
#endif
#ifdef FAKE_DPDK_DESC_PORT_DST
        desc->port_dst = rte_be_to_cpu_16(ports->dst);
#endif
    }
#endif
#ifdef FAKE_DPDK_DESC_HASH
    desc->rss_hash = pkt->hash.rss;
#endif
#ifdef FAKE_DPDK_DESC_MBUF
    desc->mb = pkt;
#endif
}


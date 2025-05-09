#include <stdint.h>
#include <rte_mbuf.h>

/*struct descriptor {
    //        char           size[104];
    uint32_t ip_src;
    uint32_t ip_dst;
    uint64_t timestamp;
    uint32_t data_len;
};*/

static int offset_desc() {
    return 16;
}

static int desc_pos() {
    return 0;
}


#define anno_size 48
    // Anno must fit in sk_buff's char cb[48].
    /** @cond never */
    typedef union Anno_t {
	char c[anno_size];
	uint8_t u8[anno_size];
	uint16_t u16[anno_size / 2];
	uint32_t u32[anno_size / 4];
	uint64_t u64[anno_size / 8];
    } Anno;


    enum PacketType {
	HOST = 0,		/**< Packet was sent to this host. */
	BROADCAST = 1,		/**< Packet was sent to a link-level multicast
				     address. */
	MULTICAST = 2,		/**< Packet was sent to a link-level multicast
				     address. */
	OTHERHOST = 3,		/**< Packet was sent to a different host, but
				     received anyway.  The receiving device is
				     probably in promiscuous mode. */
	OUTGOING = 4,		/**< Packet was generated by this host and is
				     being sent elsewhere. */
	LOOPBACK = 5,
	FASTROUTE = 6
    };



struct Packet {
    /** @brief Values for packet_type_anno().
     * Must agree with Linux's PACKET_ constants in <linux/if_packet.h>. */

	Anno cb;
	unsigned char *mac;
	unsigned char *nh;
	unsigned char *h;
	enum PacketType pkt_type;

	struct Packet *nextp;
	struct Packet *prevp;


    uint32_t _use_count;
    struct Packet *_data_packet;

    /* mimic Linux sk_buff */
    unsigned char *_head; /* start of allocated buffer */
    unsigned char *_data; /* where the packet starts */
    unsigned char *_tail; /* one beyond end of packet */
    unsigned char *_end;  /* one beyond end of allocated buffer */

    void* _destructor;
    void* _destructor_argument;

};

struct descriptor {
	struct Packet;
};



inline void asq_finish_packet(struct descriptor* d) {
    struct Packet* p = d;
    p->pkt_type = HOST;
    p->mac = p->_data;
}

static void asq_fill(struct rte_mbuf* pkt, struct descriptor* desc, unsigned) {

    struct Packet* p = desc;

    //    p->_tail = pkt->_data + pkt->data_len;

/*    if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
        struct rte_ipv4_hdr *ip_hdr;

        ip_hdr = rte_pktmbuf_mtod(pkt, struct rte_ipv4_hdr *);
        desc->ip_src = rte_be_to_cpu_32(ip_hdr->src_addr);
        desc->ip_dst = rte_be_to_cpu_32(ip_hdr->dst_addr);
    } else {
        printf("\nCore %d,IP header doesn't match IPV4 type\n", rte_lcore_id());
    }*/
}

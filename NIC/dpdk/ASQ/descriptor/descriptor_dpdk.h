#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ip.h>

struct descriptor {
	struct rte_mbuf buf;
	unsigned char pad[96];
} __attribute((packed));;


static int offset_desc() {
    return 64;
}

static int desc_pos() {
    return 18;
}


static void asq_fill(struct rte_mbuf* pkt, struct descriptor* desc, unsigned offset) {

    struct rte_mbuf* m = (struct rte_mbuf*)&desc->buf;
    memcpy(m, pkt, sizeof(struct rte_mbuf));
//    bzero(&desc->pad, 96);
    //m->buf_addr = IN DMA, compute directly the dest;
    m->next = 0;
    m->nb_segs = 0;
    m->buf_len = pkt->data_len;
    m->data_off = 0;
    m->refcnt = 1;
    m->port = 0; //TODO :from app
 //   m->pool = 0; //TODO : from app
//   debug("LEN : %d %d %d\n",m->buf_len,m->pkt_len, m->data_len);
//    m->shinfo.free_cb = 0; //TODO : from app
//    m->shinfo.fcb_opaque = (uintptr_t)offset;
//    m->ol_flags |= RTE_MBUF_F_EXTERNAL;
/*    m->next = 0;
    m->refcnt = 1;
    m->nb_segs = 1;
    m->port = 0; //TODO : from app
    m->ol_flags = pkt->ol_flags;
    m->pkt_len = pkt->pkt_len;
    m->data_len = pkt->data_len;
    m->vlan_tci = pkt->vlan_tci;
    m->vlan_tci_outer = pkt->vlan_tci_outer;
    m->buf_len = pkt->buf_len;
    m->pool = 0; //TODO : from app
    m->dynfield2 = pkt->dynfield2;
    m->shinfo = 0;
    m->priv_size = 0;
    m->timesync = 0;
    m->dynfield1 = pkt->dynfield1;
    m->packet_type = pkt->packet_type;
    */
}

static int need_prefetch() {
    return 1;
}

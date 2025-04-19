#include "rte_flow_utils.h"
#include <rte_flow.h>
#include <stdint.h>

struct rte_flow *forward_traffic_to_port(uint16_t port_id,
                                         uint16_t forwarding_port,
                                         struct rte_flow_error *error) {
    /* Declaring structs being used. 8< */
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[MAX_PATTERN_NUM];
    struct rte_flow_action action[MAX_ACTION_NUM];
    struct rte_flow *flow = NULL;
    struct rte_flow_action_port_id port = {.id = forwarding_port};

    /* >8 end of declaring structs being used. */
    int res;

    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));

    /* set the rule attribute, only ingress packets will be checked. 8< */
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.transfer = 1;
    /* >8 end of setting the rule attribute. */

    /*
     * create the action sequence.
     * one action only,  move packet to port
     */
    action[0].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
    action[0].conf = &port;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    /*
     * set the first level of the pattern (eth).
     * since in this example we just want to get the
     * ipv4 we set this level to allow all.
     */

    /* set this level to allow all. 8< */
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    /* >8 end of setting the first level of the pattern. */
    pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
    /* validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    /* >8 end of validation the rule and create it. */
    return flow;
}

struct rte_flow *send_tag_to_queue(uint16_t port_id, uint16_t queue_id,
                                   uint16_t tag, struct rte_flow_error *error) {

    /* Declaring structs being used. 8< */
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[MAX_PATTERN_NUM];
    struct rte_flow_action action[MAX_ACTION_NUM];
    struct rte_flow *flow = NULL;
    struct rte_flow_action_queue queue = {.index = queue_id};
    struct rte_flow_item_eth eth_spec;
    struct rte_flow_item_eth eth_mask;

    /* >8 end of declaring structs being used. */
    int res;

    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));

    /* set the rule attribute, only ingress packets will be checked. 8< */
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;
    /* >8 end of setting the rule attribute. */

    /*
     * create the action sequence.
     * one action only,  move packet to port
     */
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    /*
     * set the first level of the pattern (eth).
     * since in this example we just want to get the
     * ipv4 we set this level to allow all.
     */

    /* set this level to allow all. 8< */
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    memset(&eth_spec, 0, sizeof(struct rte_flow_item_ipv4));
    memset(&eth_mask, 0, sizeof(struct rte_flow_item_ipv4));
    eth_spec.src.addr_bytes[0] = tag;
    eth_mask.src.addr_bytes[0] = (uint8_t)0xff;
    pattern[0].spec = &eth_spec;
    pattern[0].mask = &eth_mask;
    /* >8 end of setting the first level of the pattern. */
    pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
    /* validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    /* >8 end of validation the rule and create it. */
    return flow;
}

struct rte_flow *change_rss_hash(uint16_t port_id, uint16_t nb_queues,
                                 struct rte_flow_error *error) {

    /* Declaring structs being used. 8< */
    static uint8_t default_rsskey_40bytes[40] = {
        0xd1, 0x81, 0xc6, 0x2c, 0xf7, 0xf4, 0xdb, 0x5b, 0x19, 0x83,
        0xa2, 0xfc, 0x94, 0x3e, 0x1a, 0xdb, 0xd9, 0x38, 0x9e, 0x6b,
        0xd1, 0x03, 0x9c, 0x2c, 0xa7, 0x44, 0x99, 0xad, 0x59, 0x3d,
        0x56, 0xd9, 0xf3, 0x25, 0x3c, 0x06, 0x2a, 0xdc, 0x1f, 0xfc};

    static int rsskey_len = sizeof(default_rsskey_40bytes);
    static uint8_t *rsskey = default_rsskey_40bytes;

    printf("Changing rss hash, nb_queues %d\n", nb_queues);
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[MAX_PATTERN_NUM];
    struct rte_flow_action action[MAX_ACTION_NUM];
    struct rte_flow *flow = NULL;
    struct rte_flow_action_rss rss_action_conf = {0};
    uint16_t queues[RTE_MAX_QUEUES_PER_PORT];
    for (int i = 0; i < nb_queues; ++i) {
        queues[i] = i;
    }

    rss_action_conf.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
    rss_action_conf.level = 0;
    rss_action_conf.types = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,

    rss_action_conf.key_len = rsskey_len;
    rss_action_conf.key = rsskey;
    rss_action_conf.queue_num = nb_queues;
    rss_action_conf.queue = queues;
    /* >8 end of declaring structs being used. */
    int res;

    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));

    /* set the rule attribute, only ingress packets will be checked. 8< */
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;
    /* >8 end of setting the rule attribute. */

    /*
     * create the action sequence.
     * one action only,  move packet to port
     */
    action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    action[0].conf = &rss_action_conf;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    /* set this level to allow all. 8< */
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

    // /* >8 end of setting the first level of the pattern. */
    pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
    /* validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    /* >8 end of validation the rule and create it. */
    return flow;
}

struct rte_flow *forward_traffic_to_representor(uint16_t port_id,
                                                uint16_t forwarding_port,
                                                enum SRC_OR_DST src_or_dst,
                                                uint16_t port_to_match,
                                                struct rte_flow_error *error) {
    /* Declaring structs being used. 8< */
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[MAX_PATTERN_NUM];
    struct rte_flow_action action[MAX_ACTION_NUM];
    struct rte_flow *flow = NULL;
    struct rte_flow_action_ethdev port = {
        .port_id = forwarding_port,
    };
    struct rte_flow_item_tcp tcp_spec;
    struct rte_flow_item_tcp tcp_mask;
    /* >8 end of declaring structs being used. */
    int res;

    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));

    /* set the rule attribute, only ingress packets will be checked. 8< */
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.transfer = 1;
    /* >8 end of setting the rule attribute. */

    /*
     * create the action sequence.
     * one action only,  move packet to port
     */
    action[0].type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT;
    action[0].conf = &port;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    /*
     * set the first level of the pattern (eth).
     * since in this example we just want to get the
     * ipv4 we set this level to allow all.
     */

    /* set this level to allow all. 8< */
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    /* >8 end of setting the first level of the pattern. */
    /* Matching every IPV4 packets. 8< */
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    // Handling TCP
    if (src_or_dst == SrcPort) {
        memset(&tcp_spec, 0, sizeof(tcp_spec));
        tcp_spec.hdr.src_port = 1024;
        memset(&tcp_mask, 0, sizeof(tcp_mask));
        tcp_mask.hdr.src_port = 0xffff;
        pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
        pattern[2].spec = &tcp_spec;
        pattern[2].mask = &tcp_mask;
    } else {
        memset(&tcp_spec, 0, sizeof(tcp_spec));
        tcp_spec.hdr.dst_port = 1024;
        memset(&tcp_mask, 0, sizeof(tcp_mask));
        tcp_mask.hdr.dst_port = 0xffff;
        pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
        pattern[2].spec = &tcp_spec;
        pattern[2].mask = &tcp_mask;
    }
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    /* validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    /* >8 end of validation the rule and create it. */
    return flow;
}

#include "flow_utils.h"
#include "consts.h"

struct rte_flow *
generate_ipv4_flow(uint16_t port_id, uint16_t rx_q,
                   uint32_t src_ip, uint32_t src_mask,
                   uint32_t dest_ip, uint32_t dest_mask,
                   struct rte_flow_error *error) {
    /* Declaring structs being used. 8< */
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[MAX_PATTERN_NUM];
    struct rte_flow_action action[MAX_ACTION_NUM];
    struct rte_flow *flow = NULL;
    struct rte_flow_action_queue queue = {.index = rx_q};
    struct rte_flow_item_ipv4 ip_spec;
    struct rte_flow_item_ipv4 ip_mask;
    /* >8 End of declaring structs being used. */
    int res;
    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));
    /* Set the rule attribute, only ingress packets will be checked. 8< */
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;
    /* >8 End of setting the rule attribute. */
    /*
     * create the action sequence.
     * one action only,  move packet to queue
     */
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;
    /*
     * set the first level of the pattern (ETH).
     * since in this example we just want to get the
     * ipv4 we set this level to allow all.
     */
    /* Set this level to allow all. 8< */
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    /* >8 End of setting the first level of the pattern. */
    /*
     * setting the second level of the pattern (IP).
     * in this example this is the level we care about
     * so we set it according to the parameters.
     */
    /* Setting the second level of the pattern. 8< */
    memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
    memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
    ip_spec.hdr.dst_addr = htonl(dest_ip);
    ip_mask.hdr.dst_addr = dest_mask;
    ip_spec.hdr.src_addr = htonl(src_ip);
    ip_mask.hdr.src_addr = src_mask;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[1].spec = &ip_spec;
    pattern[1].mask = &ip_mask;
    /* >8 End of setting the second level of the pattern. */
    /* The final level must be always type end. 8< */
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    /* >8 End of final level must be always type end. */
    /* Validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    /* >8 End of validation the rule and create it. */
    return flow;
}

struct rte_flow *
generate_tcp_flow(uint16_t port_id, uint16_t rx_q,
                  uint16_t src_port, uint16_t dst_port,
                  uint16_t src_port_mask, uint16_t dst_port_mask,
                  struct rte_flow_error *error) {
    // printf("rx_q : %d\n", rx_q);
    /* Declaring structs being used. 8< */
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[MAX_PATTERN_NUM];
    struct rte_flow_action action[MAX_ACTION_NUM];
    struct rte_flow *flow = NULL;
    struct rte_flow_action_queue queue = {.index = rx_q};
    struct rte_flow_item_tcp tcp_spec;
    struct rte_flow_item_tcp tcp_mask;
    /* >8 End of declaring structs being used. */
    int res;

    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));

    /* Set the rule attribute, only ingress packets will be checked. 8< */
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;
    /* >8 End of setting the rule attribute. */

    /*
     * create the action sequence.
     * one action only,  move packet to queue
     */
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    /*
     * set the first level of the pattern (ETH).
     * since in this example we just want to get the
     * ipv4 we set this level to allow all.
     */

    /* Set this level to allow all. 8< */
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    /* >8 End of setting the first level of the pattern. */

    /* Setting ip to allow all */
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;

    /*
     * setting the second level of the pattern (IP).
     * in this example this is the level we care about
     * so we set it according to the parameters.
     */

    /* Setting the second level of the pattern. 8< */
    memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
    memset(&tcp_mask, 0, sizeof(struct rte_flow_item_tcp));
    tcp_spec.hdr.src_port = htons(src_port);
    tcp_spec.hdr.dst_port = htons(dst_port);
    tcp_mask.hdr.src_port = src_port_mask;
    tcp_mask.hdr.dst_port = dst_port_mask;

    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[2].spec = &tcp_spec;
    pattern[2].mask = &tcp_mask;
    /* >8 End of setting the second level of the pattern. */

    /* The final level must be always type end. 8< */
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    /* >8 End of final level must be always type end. */

    /* Validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    /* >8 End of validation the rule and create it. */

    return flow;
}

struct rte_flow *
forward_ipv4_flow_port(uint16_t port_id, uint16_t forwarding_port,
                       uint32_t src_ip, uint32_t src_mask,
                       uint32_t dest_ip, uint32_t dest_mask,
                       struct rte_flow_error *error) {
    /* Declaring structs being used. 8< */
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[MAX_PATTERN_NUM];
    struct rte_flow_action action[MAX_ACTION_NUM];
    struct rte_flow *flow = NULL;
    struct rte_flow_action_port_id port = {.id = forwarding_port};
    struct rte_flow_item_ipv4 ip_spec;
    struct rte_flow_item_ipv4 ip_mask;
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

    /*
     * setting the second level of the pattern (IP).
     * in this example this is the level we care about
     * so we set it according to the parameters.
     */

    /* Setting the second level of the pattern. 8< */
    memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
    memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
    ip_spec.hdr.dst_addr = htonl(dest_ip);
    ip_mask.hdr.dst_addr = dest_mask;
    ip_spec.hdr.src_addr = htonl(src_ip);
    ip_mask.hdr.src_addr = src_mask;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[1].spec = &ip_spec;
    pattern[1].mask = &ip_mask;
    /* >8 End of setting the second level of the pattern. */

    /* The final level must be always type end. 8< */
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    /* >8 End of final level must be always type end. */

    /* Validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    /* >8 End of validation the rule and create it. */
    return flow;
}

struct rte_flow *
generate_arp_rule(uint16_t port_id, uint16_t forwarding_port, struct rte_flow_error *error) {
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
    attr.ingress = 1;
    /* >8 End of setting the rule attribute. */

    /*
     * create the action sequence.
     * one action only,  move packet to port
     */
    action[0].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
    action[0].conf = &port;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ARP_ETH_IPV4;

    pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
    /* >8 End of final level must be always type end. */

    /* Validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    /* >8 End of validation the rule and create it. */
    return flow;
}

struct rte_flow *
generate_http_rule(uint16_t port_id, uint16_t rx_q, struct rte_flow_item item, struct rte_flow_error *error) {
    // printf("rx_q : %d\n", rx_q);
    /* Declaring structs being used. 8< */
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[MAX_PATTERN_NUM];
    struct rte_flow_action action[MAX_ACTION_NUM];
    struct rte_flow *flow = NULL;
    struct rte_flow_action_queue queue = {.index = rx_q};

    /* >8 End of declaring structs being used. */
    int res;

    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));

    /* Set the rule attribute, only ingress packets will be checked. 8< */
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;
    /* >8 End of setting the rule attribute. */

    /*
     * create the action sequence.
     * one action only,  move packet to queue
     */
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    /*
     * set the first level of the pattern (ETH).
     * since in this example we just want to get the
     * ipv4 we set this level to allow all.
     */

    /* Set this level to allow all. 8< */
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;

    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;

    pattern[3] = item;
    /* The final level must be always type end. 8< */
    pattern[4].type = RTE_FLOW_ITEM_TYPE_END;
    /* >8 End of final level must be always type end. */

    /* Validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    /* >8 End of validation the rule and create it. */

    return flow;
}

// struct rte_flow *
// forward_ipv4_flow_port(uint16_t port_id, uint16_t forwarding_port,
//                        uint32_t src_ip, uint32_t src_mask,
//                        uint32_t dest_ip, uint32_t dest_mask,
//                        struct rte_flow_error *error)
// {
//     /* Declaring structs being used. 8< */
//     struct rte_flow_attr attr;
//     struct rte_flow_item pattern[MAX_PATTERN_NUM];
//     struct rte_flow_action action[MAX_ACTION_NUM];
//     struct rte_flow *flow = NULL;
//     struct rte_flow_action_port_id port = {.id = forwarding_port};
//     struct rte_flow_item_ipv4 ip_spec;
//     struct rte_flow_item_ipv4 ip_mask;
//     /* >8 End of declaring structs being used. */
//     int res;

//     memset(pattern, 0, sizeof(pattern));
//     memset(action, 0, sizeof(action));

//     /* Set the rule attribute, only ingress packets will be checked. 8< */
//     memset(&attr, 0, sizeof(struct rte_flow_attr));
//     attr.transfer = 1;
//     /* >8 End of setting the rule attribute. */

//     /*
//      * create the action sequence.
//      * one action only,  move packet to port
//      */
//     action[0].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
//     action[0].conf = &port;
//     action[1].type = RTE_FLOW_ACTION_TYPE_END;

//     /*
//      * set the first level of the pattern (ETH).
//      * since in this example we just want to get the
//      * ipv4 we set this level to allow all.
//      */

//     /* Set this level to allow all. 8< */
//     pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
//     /* >8 End of setting the first level of the pattern. */

//     /*
//      * setting the second level of the pattern (IP).
//      * in this example this is the level we care about
//      * so we set it according to the parameters.
//      */

//     /* Setting the second level of the pattern. 8< */
//     memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
//     memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
//     ip_spec.hdr.dst_addr = htonl(dest_ip);
//     ip_mask.hdr.dst_addr = dest_mask;
//     ip_spec.hdr.src_addr = htonl(src_ip);
//     ip_mask.hdr.src_addr = src_mask;
//     pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
//     pattern[1].spec = &ip_spec;
//     pattern[1].mask = &ip_mask;
//     /* >8 End of setting the second level of the pattern. */

//     /* The final level must be always type end. 8< */
//     pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
//     /* >8 End of final level must be always type end. */

//     /* Validate the rule and create it. 8< */
//     res = rte_flow_validate(port_id, &attr, pattern, action, error);
//     if (!res)
//         flow = rte_flow_create(port_id, &attr, pattern, action, error);
//     /* >8 End of validation the rule and create it. */
//     return flow;
// }

struct rte_flow *
tag_dscp_and_forward_flow(uint16_t port_id, uint16_t forwarding_port, uint8_t dscp,
                          uint32_t src_ip, uint16_t src_port,
                          uint32_t dest_ip, uint16_t dst_port,
                          uint32_t priority,
                          struct rte_flow_error *error) {
    /* Declaring structs being used. 8< */
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[MAX_PATTERN_NUM];
    struct rte_flow_action action[MAX_ACTION_NUM];
    struct rte_flow *flow = NULL;
    struct rte_flow_action_port_id port = {.id = forwarding_port};
    struct rte_flow_action_set_dscp dscp_conf = {.dscp = dscp};
    struct rte_flow_item_ipv4 ip_spec;
    struct rte_flow_item_ipv4 ip_mask;
    struct rte_flow_item_tcp tcp_spec;
    struct rte_flow_item_tcp tcp_mask;
    /* >8 End of declaring structs being used. */
    int res;

    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));

    /* Set the rule attribute, only ingress packets will be checked. 8< */
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.transfer = 1;
    attr.priority = priority;
    /* >8 End of setting the rule attribute. */

    /*
     * create the action sequence.
     * one action only,  move packet to port
     */
    action[0].type = RTE_FLOW_ACTION_TYPE_SET_IPV4_DSCP;
    action[0].conf = &dscp_conf;
    action[1].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
    action[1].conf = &port;
    action[2].type = RTE_FLOW_ACTION_TYPE_END;

    /*
     * set the first level of the pattern (ETH).
     * since in this example we just want to get the
     * ipv4 we set this level to allow all.
     */

    /* Set this level to allow all. 8< */
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    /* >8 End of setting the first level of the pattern. */

    /*
     * setting the second level of the pattern (IP).
     * in this example this is the level we care about
     * so we set it according to the parameters.
     */

    /* Setting the second level of the pattern. 8< */
    memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
    memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
    ip_spec.hdr.dst_addr = dest_ip;
    ip_spec.hdr.src_addr = src_ip;
    ip_mask.hdr.dst_addr = SLASH_32;
    ip_mask.hdr.src_addr = SLASH_32;

    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[1].spec = &ip_spec;
    pattern[1].mask = &ip_mask;

    /* >8 End of setting the second level of the pattern. */

    memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
    memset(&tcp_mask, 0, sizeof(struct rte_flow_item_tcp));
    tcp_spec.hdr.src_port = src_port;
    tcp_spec.hdr.dst_port = dst_port;
    tcp_mask.hdr.src_port = SLASH_16;
    tcp_mask.hdr.dst_port = SLASH_16;
    tcp_spec.hdr.tcp_flags = (uint8_t)0;
    tcp_mask.hdr.tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_RST_FLAG;

    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[2].spec = &tcp_spec;
    pattern[2].mask = &tcp_mask;
    /* The final level must be always type end. 8< */
    // pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    // pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    /* >8 End of final level must be always type end. */

    /* Validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    /* >8 End of validation the rule and create it. */
    return flow;
}

struct rte_flow *
count_flow(uint16_t port_id,
           uint32_t src_ip, uint16_t src_port,
           uint32_t dest_ip, uint16_t dst_port,
           uint32_t priority,
           struct rte_flow_error *error) {
    /* Declaring structs being used. 8< */
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[MAX_PATTERN_NUM];
    struct rte_flow_action action[MAX_ACTION_NUM];
    struct rte_flow *flow = NULL;
    struct rte_flow_item_ipv4 ip_spec;
    struct rte_flow_item_ipv4 ip_mask;
    struct rte_flow_item_tcp tcp_spec;
    struct rte_flow_item_tcp tcp_mask;
    struct rte_flow_action_queue queue = {.index = 0};
    /* >8 End of declaring structs being used. */
    int res;

    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));

    /* Set the rule attribute, only ingress packets will be checked. 8< */
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;
    attr.priority = priority;
    /* >8 End of setting the rule attribute. */

    /*
     * create the action sequence.
     * one action only,  move packet to port
     */
    action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
    action[1].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[1].conf = &queue;
    action[2].type = RTE_FLOW_ACTION_TYPE_END;

    /*
     * set the first level of the pattern (ETH).
     * since in this example we just want to get the
     * ipv4 we set this level to allow all.
     */

    /* Set this level to allow all. 8< */
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    /* >8 End of setting the first level of the pattern. */

    /*
     * setting the second level of the pattern (IP).
     * in this example this is the level we care about
     * so we set it according to the parameters.
     */

    /* Setting the second level of the pattern. 8< */
    memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
    memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
    ip_spec.hdr.dst_addr = dest_ip;
    ip_spec.hdr.src_addr = src_ip;
    ip_mask.hdr.dst_addr = SLASH_32;
    ip_mask.hdr.src_addr = SLASH_32;

    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[1].spec = &ip_spec;
    pattern[1].mask = &ip_mask;

    /* >8 End of setting the second level of the pattern. */

    memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
    memset(&tcp_mask, 0, sizeof(struct rte_flow_item_tcp));
    tcp_spec.hdr.src_port = src_port;
    tcp_spec.hdr.dst_port = dst_port;
    tcp_mask.hdr.src_port = SLASH_16;
    tcp_mask.hdr.dst_port = SLASH_16;

    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[2].spec = &tcp_spec;
    pattern[2].mask = &tcp_mask;
    /* The final level must be always type end. 8< */
    // pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    // pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    /* >8 End of final level must be always type end. */

    /* Validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    /* >8 End of validation the rule and create it. */
    return flow;
}



struct rte_flow *
forward_packet_to_port(uint16_t port_id, uint16_t forwarding_port,
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

    /* >8 End of final level must be always type end. */
    pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
    /* Validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    /* >8 End of validation the rule and create it. */
    return flow;
}

struct rte_flow *
filter_fin_ack_packets(uint16_t port_id, uint16_t forwarding_port,
                       struct rte_flow_error *error) {
    /* Declaring structs being used. 8< */
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[MAX_PATTERN_NUM];
    struct rte_flow_action action[MAX_ACTION_NUM];
    struct rte_flow *flow = NULL;
    struct rte_flow_action_port_id port = {.id = forwarding_port};
    struct rte_flow_item_tcp tcp_spec;
    struct rte_flow_item_tcp tcp_mask;

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

    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;

    memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
    memset(&tcp_mask, 0, sizeof(struct rte_flow_item_tcp));
    //Forwarding all the packets with FIN FLAG not set
    tcp_spec.hdr.tcp_flags = (uint8_t)0;
    tcp_mask.hdr.tcp_flags = RTE_TCP_FIN_FLAG;

    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[2].spec = &tcp_spec;
    pattern[2].mask = &tcp_mask;

    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    /* Validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    /* >8 End of validation the rule and create it. */
    return flow;
}

struct rte_flow *
filter_tcp_packets(uint16_t port_id, uint16_t forwarding_port,
                   struct rte_flow_item_tcp tcp_spec,
                   struct rte_flow_item_tcp tcp_mask,
                   uint32_t priority,
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
    attr.priority = priority;
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

    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;

    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[2].spec = &tcp_spec;
    pattern[2].mask = &tcp_mask;

    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    /* Validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    /* >8 End of validation the rule and create it. */
    return flow;
}

struct rte_flow *
forward_traffic_to_port(uint16_t port_id,
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

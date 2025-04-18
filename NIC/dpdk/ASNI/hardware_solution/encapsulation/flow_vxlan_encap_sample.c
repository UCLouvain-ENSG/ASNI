/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */
#include <string.h>
#include <unistd.h>

#include <doca_flow.h>
#include <doca_log.h>
#include <dpdk_utils2.h>

#include "flow_common.h"
#include "processing.h"
#include "structs_enums.h"

#define META_U32_BIT_OFFSET(idx)                                               \
    (offsetof(struct doca_flow_meta, u32[(idx)]) << 3)

DOCA_LOG_REGISTER(FLOW_DESC_CREATION);

#define NB_ACTIONS_ENCAP 1

#define NB_ACTIONS_COPY_TO_META 1
#define NB_ACTIONS_DESC_COPY_TO_META 3

#define NB_ACTIONS_COPY_FROM_META 1
#define NB_ACTIONS_DESC_COPY_FROM_META 3

#define NB_ACTIONS_SET_META 1

#define SIZE_OF_ETH_HDR 14

#define NB_ENTRIES_HASH 3

/* First pipe, here we first want to encapsulate the packet into a VXLAN header
 */

static doca_error_t create_vxlan_encap(struct doca_flow_port *port,
                                       struct doca_flow_pipe *next_pipe,
                                       struct doca_flow_pipe **pipe) {
    struct doca_flow_match match;
    struct doca_flow_match match_mask;
    struct doca_flow_actions actions, *actions_arr[NB_ACTIONS_ENCAP];
    struct doca_flow_fwd fwd;
    struct doca_flow_fwd fwd_miss;
    struct doca_flow_pipe_cfg *pipe_cfg;
    doca_error_t result;

    memset(&match, 0, sizeof(match));
    memset(&match_mask, 0, sizeof(match_mask));
    memset(&actions, 0, sizeof(actions));
    memset(&fwd, 0, sizeof(fwd));

    /* build basic outer VXLAN encap data*/
    actions.encap_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
    actions.encap_cfg.is_l2 = true;
    SET_MAC_ADDR(actions.encap_cfg.encap.outer.eth.src_mac, 0xff, 0xff, 0xff,
                 0xff, 0xff, 0xff);
    SET_MAC_ADDR(actions.encap_cfg.encap.outer.eth.dst_mac, 0xff, 0xff, 0xff,
                 0xff, 0xff, 0xff);
    actions.encap_cfg.encap.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    actions.encap_cfg.encap.outer.ip4.src_ip = 0xffffffff;
    actions.encap_cfg.encap.outer.ip4.dst_ip = 0xffffffff;
    actions.encap_cfg.encap.outer.ip4.ttl = 0xff;
    actions.encap_cfg.encap.outer.ip4.flags_fragment_offset = 0xffff;
    actions.encap_cfg.encap.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
    actions.encap_cfg.encap.outer.udp.l4_port.dst_port =
        RTE_BE16(DOCA_FLOW_VXLAN_DEFAULT_PORT);
    actions.encap_cfg.encap.tun.type = DOCA_FLOW_TUN_VXLAN;
    actions.encap_cfg.encap.tun.vxlan_tun_id = 0xffffffff;
    actions_arr[0] = &actions;

    // match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
    // match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    // match.outer.ip4.src_ip = 0xffffffff;
    // match.outer.ip4.dst_ip = 0xffffffff;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        return result;
    }

    result = set_flow_pipe_cfg(pipe_cfg, "VXLAN_ENCAP_PIPE",
                               DOCA_FLOW_PIPE_BASIC, false);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result =
        doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg domain: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, &match_mask);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL,
                                            NB_ACTIONS_ENCAP);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg actions: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }

    /* forwarding traffic to the next pipe*/
    fwd.type = DOCA_FLOW_FWD_PIPE;
    fwd.next_pipe = next_pipe;
    fwd_miss.type = DOCA_FLOW_FWD_DROP;

    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create flow pipe: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    return DOCA_SUCCESS;
destroy_pipe_cfg:
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    return result;
}

/*
 * Add DOCA Flow pipe entry with example encap values
 *
 * @pipe [in]: pipe of the entry
 * @port [in]: port of the entry
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t add_vxlan_encap_entry(struct doca_flow_pipe *pipe,
                                          struct doca_flow_port *port) {
    struct doca_flow_match match;
    struct doca_flow_actions actions;
    struct doca_flow_pipe_entry *entry;
    doca_error_t result;
    struct entries_status status;

    memset(&match, 0, sizeof(match));
    memset(&actions, 0, sizeof(actions));

    // actions.outer.transport.src_port = rte_cpu_to_be_16(1235);
    // actions.action_idx = 0;

    result = doca_flow_pipe_add_entry(0, pipe, &match, &actions, NULL, NULL, 0,
                                      &status, &entry);
    if (result != DOCA_SUCCESS) {
        return result;
    }
    return DOCA_SUCCESS;
}

static doca_error_t copy_to_meta(struct doca_flow_port *port,
                                 struct doca_flow_pipe *next_pipe,
                                 struct doca_flow_pipe **pipe) {
    struct doca_flow_match match;
    struct doca_flow_match match_mask;
    struct doca_flow_actions actions;
    struct doca_flow_actions *actions_arr[NB_ACTIONS_COPY_TO_META];
    struct doca_flow_fwd fwd;
    struct doca_flow_fwd fwd_miss;
    struct doca_flow_pipe_cfg *pipe_cfg;
    struct doca_flow_action_descs descs;
    struct doca_flow_action_descs *descs_arr[NB_ACTIONS_COPY_TO_META];
    struct doca_flow_action_desc desc_array[NB_ACTIONS_DESC_COPY_TO_META] = {0};
    doca_error_t result;

    memset(&match, 0, sizeof(match));
    memset(&match_mask, 0, sizeof(match_mask));
    memset(&actions, 0, sizeof(actions));
    memset(&fwd, 0, sizeof(fwd));
    memset(&fwd_miss, 0, sizeof(fwd_miss));
    memset(&descs, 0, sizeof(descs));

    desc_array[0].type = DOCA_FLOW_ACTION_COPY;
    desc_array[0].field_op.src.field_string = "outer.ipv4.src_ip";
    desc_array[0].field_op.src.bit_offset = 0;
    desc_array[0].field_op.dst.field_string = "meta.data";
    desc_array[0].field_op.dst.bit_offset = META_U32_BIT_OFFSET(0);
    desc_array[0].field_op.width = 32;

    desc_array[1].type = DOCA_FLOW_ACTION_ADD;
    desc_array[1].field_op.src.field_string = "outer.ipv4.total_len";
    desc_array[1].field_op.src.bit_offset = 0;
    desc_array[1].field_op.dst.field_string = "meta.data";
    desc_array[1].field_op.dst.bit_offset = META_U32_BIT_OFFSET(1);
    desc_array[1].field_op.width = 16;

    desc_array[2].type = DOCA_FLOW_ACTION_COPY;
    desc_array[2].field_op.dst.field_string = "meta.data";
    desc_array[2].field_op.dst.bit_offset = META_U32_BIT_OFFSET(2);
    desc_array[2].field_op.src.field_string = "parser_meta.hash.result";
    desc_array[2].field_op.src.bit_offset = 0;
    desc_array[2].field_op.width = 32;

    actions_arr[0] = &actions;
    descs_arr[0] = &descs;
    descs.nb_action_desc = NB_ACTIONS_DESC_COPY_TO_META;
    descs.desc_array = desc_array;

    match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
    match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    match.outer.ip4.src_ip = 0xffffffff;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        return result;
    }
    result = set_flow_pipe_cfg(pipe_cfg, "COPY_TO_META_PIPE",
                               DOCA_FLOW_PIPE_BASIC, false);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL,
                                            descs_arr, NB_ACTIONS_COPY_TO_META);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg actions: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    fwd.type = DOCA_FLOW_FWD_PIPE;
    fwd.next_pipe = next_pipe;
    fwd_miss.type = DOCA_FLOW_FWD_DROP;

    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create flow pipe: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    return DOCA_SUCCESS;
destroy_pipe_cfg:
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    return result;
}

static doca_error_t add_copy_to_meta_entry(struct doca_flow_pipe *pipe,
                                           struct doca_flow_port *port) {
    struct doca_flow_match match;
    struct doca_flow_actions actions;
    struct doca_flow_pipe_entry *entry;
    struct entries_status status;
    doca_error_t result;
    int num_of_entries = 1;

    memset(&status, 0, sizeof(status));
    memset(&match, 0, sizeof(match));
    memset(&actions, 0, sizeof(actions));

    doca_be32_t src_ip_addr = BE_IPV4_ADDR(1, 1, 1, 1);

    match.outer.ip4.src_ip = src_ip_addr;

    result = doca_flow_pipe_add_entry(0, pipe, &match, &actions, NULL, NULL, 0,
                                      &status, &entry);
    if (result != DOCA_SUCCESS)
        return result;

    result =
        doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, num_of_entries);
    if (result != DOCA_SUCCESS)
        return result;

    if (status.nb_processed != num_of_entries || status.failure)
        return DOCA_ERROR_BAD_STATE;

    return DOCA_SUCCESS;
}
static doca_error_t copy_from_meta(struct doca_flow_port *port,
                                   struct doca_flow_pipe **pipe, int NB_CORES) {
    struct doca_flow_match match;
    struct doca_flow_match match_mask;
    struct doca_flow_actions actions;
    struct doca_flow_actions *actions_arr[NB_ACTIONS_COPY_FROM_META];
    struct doca_flow_fwd fwd;
    struct doca_flow_fwd fwd_miss;
    struct doca_flow_pipe_cfg *pipe_cfg;
    struct doca_flow_action_descs descs;
    struct doca_flow_action_descs *descs_arr[NB_ACTIONS_COPY_FROM_META];
    struct doca_flow_action_desc desc_array[NB_ACTIONS_DESC_COPY_FROM_META] = {
        0};
    doca_error_t result;
    uint16_t rss_queues[32];

    memset(&match, 0, sizeof(match));
    memset(&match_mask, 0, sizeof(match_mask));
    memset(&actions, 0, sizeof(actions));
    memset(&fwd, 0, sizeof(fwd));
    memset(&fwd_miss, 0, sizeof(fwd_miss));
    memset(&descs, 0, sizeof(descs));

    desc_array[0].type = DOCA_FLOW_ACTION_COPY;
    desc_array[0].field_op.dst.field_string = "outer.eth.dst_mac";
    desc_array[0].field_op.dst.bit_offset = 32;
    desc_array[0].field_op.src.field_string = "meta.data";
    desc_array[0].field_op.src.bit_offset = META_U32_BIT_OFFSET(1) + 8;
    desc_array[0].field_op.width = 8;

    desc_array[1].type = DOCA_FLOW_ACTION_COPY;
    desc_array[1].field_op.dst.field_string = "outer.eth.dst_mac";
    desc_array[1].field_op.dst.bit_offset = 40;
    desc_array[1].field_op.src.field_string = "meta.data";
    desc_array[1].field_op.src.bit_offset = META_U32_BIT_OFFSET(1);
    desc_array[1].field_op.width = 8;

    desc_array[2].type = DOCA_FLOW_ACTION_COPY;
    desc_array[2].field_op.dst.field_string = "outer.eth.dst_mac";
    desc_array[2].field_op.dst.bit_offset = 0;
    desc_array[2].field_op.src.field_string = "meta.data";
    desc_array[2].field_op.src.bit_offset = META_U32_BIT_OFFSET(2);
    desc_array[2].field_op.width = 32;

    actions_arr[0] = &actions;
    descs_arr[0] = &descs;
    descs.nb_action_desc = NB_ACTIONS_DESC_COPY_FROM_META;
    descs.desc_array = desc_array;

    // match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    // match.outer.ip4.src_ip = 0xffffffff;
    // match.outer.ip4.dst_ip = 0xffffffff;

    SET_MAC_ADDR(match.outer.eth.src_mac, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    SET_MAC_ADDR(match.outer.eth.dst_mac, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

    result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        return result;
    }
    result = set_flow_pipe_cfg(pipe_cfg, "COPY_FROM_META_PIPE",
                               DOCA_FLOW_PIPE_BASIC, false);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL,
                                            descs_arr, NB_ACTIONS_COPY_TO_META);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg actions: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    for (int i = 0; i < NB_CORES; i++) {
        rss_queues[i] = i;
    }

    fwd.type = DOCA_FLOW_FWD_RSS;
    fwd.rss_queues = rss_queues;
    fwd.rss_inner_flags =
        DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_TCP | DOCA_FLOW_RSS_UDP;
    fwd.num_of_queues = NB_CORES;
    fwd_miss.type = DOCA_FLOW_FWD_DROP;
    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe);
destroy_pipe_cfg:
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    return result;
}

static doca_error_t add_copy_from_meta_entry(struct doca_flow_pipe *pipe,
                                             struct doca_flow_port *port) {
    struct doca_flow_match match;
    struct doca_flow_actions actions;
    struct doca_flow_pipe_entry *entry;
    struct entries_status status;
    doca_error_t result;
    int num_of_entries = 1;

    memset(&status, 0, sizeof(status));
    memset(&match, 0, sizeof(match));
    memset(&actions, 0, sizeof(actions));

    result = doca_flow_pipe_add_entry(0, pipe, &match, &actions, NULL, NULL, 0,
                                      &status, &entry);
    if (result != DOCA_SUCCESS)
        return result;

    result =
        doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, num_of_entries);
    if (result != DOCA_SUCCESS)
        return result;

    if (status.nb_processed != num_of_entries || status.failure)
        return DOCA_ERROR_BAD_STATE;

    return DOCA_SUCCESS;
}

static doca_error_t set_meta(struct doca_flow_port *port,
                             struct doca_flow_pipe *next_pipe,
                             struct doca_flow_pipe **pipe) {
    struct doca_flow_match match;
    struct doca_flow_actions actions, *actions_arr[NB_ACTIONS_SET_META];
    struct doca_flow_fwd fwd;
    struct doca_flow_fwd fwd_miss;
    struct doca_flow_pipe_cfg *pipe_cfg;
    doca_error_t result;

    memset(&match, 0, sizeof(match));
    memset(&actions, 0, sizeof(actions));
    memset(&fwd, 0, sizeof(fwd));

    /* set mask value */
    // MANDATORY, otherwise nothing happens
    actions.meta.u32[1] = UINT32_MAX;
    actions_arr[0] = &actions;

    /* 5 tuple match */

    result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        return result;
    }

    result = set_flow_pipe_cfg(pipe_cfg, "SET_META_PIPE", DOCA_FLOW_PIPE_BASIC,
                               true);
    result =
        doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg domain: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL,
                                            NB_ACTIONS_SET_META);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg actions: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }

    fwd.type = DOCA_FLOW_FWD_PIPE;
    fwd.next_pipe = next_pipe;
    fwd_miss.type = DOCA_FLOW_FWD_DROP;

    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe);
destroy_pipe_cfg:
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    return result;
}

/*
 * Add DOCA Flow pipe entry with example 5 tuple to match and set meta data
 * value
 *
 * @pipe [in]: pipe of the entry
 * @status [in]: user context for adding entry
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t set_meta_entry(struct doca_flow_pipe *pipe,
                                   struct entries_status *status) {
    struct doca_flow_match match;
    struct doca_flow_actions actions;
    struct doca_flow_pipe_entry *entry;
    doca_error_t result;

    /* example 5-tuple to drop */

    memset(&match, 0, sizeof(match));
    memset(&actions, 0, sizeof(actions));

    /* set meta value */
    actions.meta.u32[1] = SIZE_OF_ETH_HDR;
    actions.action_idx = 0;

    result = doca_flow_pipe_add_entry(0, pipe, &match, &actions, NULL, NULL, 0,
                                      status, &entry);
    if (result != DOCA_SUCCESS)
        return result;

    return DOCA_SUCCESS;
}

static doca_error_t create_hash_pipe(struct doca_flow_port *port,
                                     struct doca_flow_pipe *next_pipe,
                                     struct doca_flow_pipe **pipe) {
    struct doca_flow_match match_mask;
    struct doca_flow_monitor monitor;
    struct doca_flow_fwd fwd;
    struct doca_flow_fwd fwd_miss;
    struct doca_flow_pipe_cfg *pipe_cfg;
    doca_error_t result;

    memset(&match_mask, 0, sizeof(match_mask));
    memset(&monitor, 0, sizeof(monitor));
    memset(&fwd, 0, sizeof(fwd));

    /* match mask defines which header fields to use in order to calculate the
     * entry index */
    match_mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    match_mask.outer.ip4.dst_ip = 0xffffffff;
    match_mask.outer.ip4.src_ip = 0xffffffff;

    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        return result;
    }

    result =
        set_flow_pipe_cfg(pipe_cfg, "HASH_PIPE", DOCA_FLOW_PIPE_HASH, true);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, NB_ENTRIES_HASH);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg nr_entries: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_match(pipe_cfg, NULL, &match_mask);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg monitor: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }

    /* FWD component is defined per entry */
    fwd.type = DOCA_FLOW_FWD_PORT;
    fwd.port_id = 0;
    fwd_miss.type = DOCA_FLOW_FWD_DROP;

    printf("Creating hash pipe\n");
    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe);
    printf("Created hash pipe\n");
destroy_pipe_cfg:
    // doca_flow_pipe_cfg_destroy(pipe_cfg);
    printf("Destroyed pipe cfg\n");
    return result;
}

static doca_error_t create_hash_pipe_test(struct doca_flow_port *port,
                                          struct doca_flow_pipe **pipe) {
    struct doca_flow_match match_mask;
    struct doca_flow_monitor monitor;
    struct doca_flow_fwd fwd;
    struct doca_flow_pipe_cfg *pipe_cfg;
    doca_error_t result;

    memset(&match_mask, 0, sizeof(match_mask));
    memset(&monitor, 0, sizeof(monitor));
    memset(&fwd, 0, sizeof(fwd));

    /* match mask defines which header fields to use in order to calculate the
     * entry index */
    match_mask.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    match_mask.outer.ip4.dst_ip = 0xffffffff;

    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        return result;
    }

    result =
        set_flow_pipe_cfg(pipe_cfg, "HASH_PIPE", DOCA_FLOW_PIPE_HASH, true);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, NB_ENTRIES_HASH);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg nr_entries: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_match(pipe_cfg, NULL, &match_mask);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg monitor: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }

    /* FWD component is defined per entry */
    fwd.type = DOCA_FLOW_FWD_PORT;
    fwd.port_id = 0xffff;

    result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, pipe);
destroy_pipe_cfg:
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    return result;
}
/*
 * Add DOCA Flow pipe entry with example 5 tuple match
 *
 * @pipe [in]: pipe of the entry
 * @port [in]: port of the entry
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */

/*
 * Run flow_vxlan_encap sample
 *
 * @nb_queues [in]: number of queues the sample will use
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */

doca_error_t flow_vxlan_encap(int nb_queues, volatile bool *fq, int NB_CORES,
                              int starting_port_id) {
    int nb_ports = 1;
    const int max_nb_ports = 128;
    struct flow_resources resource = {0};
    uint32_t nr_shared_resources[SHARED_RESOURCE_NUM_VALUES] = {0};
    struct doca_flow_port *ports[max_nb_ports];
    struct doca_dev *dev_arr[max_nb_ports];
    struct doca_flow_pipe *vxlan_encap_pipe;
    struct doca_flow_pipe *copy_to_meta_pipe;
    struct doca_flow_pipe *copy_from_meta_pipe;
    struct doca_flow_pipe *set_meta_pipe;
    struct doca_flow_pipe *hash_pipe;

    doca_error_t result;
    int port_id;
    printf("available ports : %d\n", rte_eth_dev_count_avail());

    result =
        init_doca_flow(nb_queues, "vnf,hws", &resource, nr_shared_resources);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init DOCA Flow: %s",
                     doca_error_get_descr(result));
        return result;
    }

    result = init_doca_flow_ports(nb_ports, ports, false, dev_arr);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init DOCA ports: %s",
                     doca_error_get_descr(result));
        doca_flow_destroy();
        return result;
    }

    for (port_id = starting_port_id; port_id < nb_ports + starting_port_id;
         port_id++) {
        /*Copying metadata to encapsulated header*/
        printf("port_id : %d\n", port_id);
        printf("ports[port_id] : %p\n", ports[port_id]);

        result = copy_from_meta(ports[port_id], &copy_from_meta_pipe, NB_CORES);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to create copy_from_meta pipe: %s",
                         doca_error_get_descr(result));
            stop_doca_flow_ports(nb_ports, ports);
            doca_flow_destroy();
            return result;
        }
        DOCA_LOG_INFO("copy_from_meta_pipe created\n");

        result = add_copy_from_meta_entry(copy_from_meta_pipe, ports[port_id]);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to add entry to match pipe: %s",
                         doca_error_get_descr(result));
            stop_doca_flow_ports(nb_ports, ports);
            doca_flow_destroy();
            return result;
        }

        /*Encapsulating the packet*/
        result = create_vxlan_encap(ports[port_id], copy_from_meta_pipe,
                                    &vxlan_encap_pipe);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to create vxlan encap pipe: %s",
                         doca_error_get_descr(result));
            stop_doca_flow_ports(nb_ports, ports);
            doca_flow_destroy();
            return result;
        }
        DOCA_LOG_INFO("encap_vxlan_encap_pipe created\n");

        result = add_vxlan_encap_entry(vxlan_encap_pipe, ports[port_id]);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to add entry to vxlan encap pipe: %s",
                         doca_error_get_descr(result));
            stop_doca_flow_ports(nb_ports, ports);
            doca_flow_destroy();
            return result;
        }
        result =
            copy_to_meta(ports[port_id], vxlan_encap_pipe, &copy_to_meta_pipe);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to create copy_to_meta pipe: %s",
                         doca_error_get_descr(result));
            stop_doca_flow_ports(nb_ports, ports);
            doca_flow_destroy();
            return result;
        }
        DOCA_LOG_INFO("copy_to_meta pipe created\n");

        result = add_copy_to_meta_entry(copy_to_meta_pipe, ports[port_id]);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to add entry to match pipe: %s",
                         doca_error_get_descr(result));
            stop_doca_flow_ports(nb_ports, ports);
            doca_flow_destroy();
            return result;
        }

        result = set_meta(ports[port_id], copy_to_meta_pipe, &set_meta_pipe);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to create set_meta_pipe pipe: %s",
                         doca_error_get_descr(result));
            stop_doca_flow_ports(nb_ports, ports);
            doca_flow_destroy();
            return result;
        }
        DOCA_LOG_INFO("set_to_meta_pipe created\n");

        struct entries_status status;
        memset(&status, 0, sizeof(status));
        result = set_meta_entry(set_meta_pipe, &status);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to add entry to set_meta pipe: %s",
                         doca_error_get_descr(result));
            stop_doca_flow_ports(nb_ports, ports);
            doca_flow_destroy();
            return result;
        }

        // result = create_hash_pipe(ports[port_id], set_meta_pipe, &hash_pipe);
        // if (result != DOCA_SUCCESS) {
        //     printf("Failed to create hash pipe\n");
        //     DOCA_LOG_ERR("Failed to create hash pipe: %s",
        //                  doca_error_get_descr(result));
        //     stop_doca_flow_ports(nb_ports, ports);
        //     doca_flow_destroy();
        //     return result;
        // }
        // result =
        //     create_hash_pipe_test(doca_flow_port_switch_get(NULL), &hash_pipe);
        // if (result != DOCA_SUCCESS) {
        //     printf("Failed to create hash pipe\n");
        //     DOCA_LOG_ERR("Failed to create hash pipe: %s",
        //                  doca_error_get_descr(result));
        //     stop_doca_flow_ports(nb_ports, ports);
        //     doca_flow_destroy();
        //     return result;
        // }
    }

    DOCA_LOG_INFO("Setup completed\n");
    /*Receiving packets*/
    return DOCA_SUCCESS;
}

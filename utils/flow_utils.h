#include <rte_arp.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_devargs.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_random.h>
#include <rte_spinlock.h>
#include <rte_string_fns.h>
#include <rte_tcp.h>
#include <rte_version.h>
#include <stdint.h>

#define MAX_PATTERN_NUM 10
#define MAX_ACTION_NUM 10

struct rte_flow *
generate_ipv4_flow(uint16_t port_id, uint16_t rx_q,
                   uint32_t src_ip, uint32_t src_mask,
                   uint32_t dest_ip, uint32_t dest_mask,
                   struct rte_flow_error *error);

struct rte_flow *
generate_tcp_flow(uint16_t port_id, uint16_t rx_q,
                  uint16_t src_port, uint16_t dst_port,
                  uint16_t src_port_mask, uint16_t dst_port_mask,
                  struct rte_flow_error *error);

struct rte_flow *
forward_ipv4_flow(uint16_t port_id, uint16_t forwarding_port,
                  uint32_t src_ip, uint32_t src_mask,
                  uint32_t dest_ip, uint32_t dest_mask,
                  struct rte_flow_error *error);

struct rte_flow *
generate_arp_rule(uint16_t port_id, uint16_t forwarding_port, struct rte_flow_error *error);

struct rte_flow *
generate_http_rule(uint16_t port_id, uint16_t rx_q, struct rte_flow_item item, struct rte_flow_error *error);

struct rte_flow *
tag_dscp_and_forward_flow(uint16_t port_id, uint16_t forwarding_port, uint8_t dscp,
                          uint32_t src_ip, uint16_t src_port,
                          uint32_t dest_ip, uint16_t dst_port,
                          uint32_t priority,
                          struct rte_flow_error *error);

struct rte_flow *
forward_packet_to_port(uint16_t port_id, uint16_t forwarding_port,
                       struct rte_flow_error *error);

struct rte_flow *
filter_fin_ack_packets(uint16_t port_id, uint16_t forwarding_port,
                       struct rte_flow_error *error);

struct rte_flow *
filter_tcp_packets(uint16_t port_id, uint16_t forwarding_port,
                   struct rte_flow_item_tcp tcp_spec,
                   struct rte_flow_item_tcp tcp_mask,
                   uint32_t priority,
                   struct rte_flow_error *error);
struct rte_flow *
forward_traffic_to_port(uint16_t port_id,
                        uint16_t forwarding_port,
                        struct rte_flow_error *error);
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/if_ether.h>
#include <pthread.h>
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
#include <rte_flow.h>
#include <rte_hash.h>
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
#include <rte_ring_core.h>
#include <rte_ring_elem.h>
#include <rte_spinlock.h>
#include <rte_string_fns.h>
#include <rte_tcp.h>
#include <rte_version.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 256
#define RTE_TEST_RX_DESC_DEFAULT 2048
#define RTE_TEST_TX_DESC_DEFAULT 2048
#define NB_QUEUES 4

#define MAX_PATTERN_NUM 10
#define MAX_ACTION_NUM 10

enum SRC_OR_DST{SrcPort, DstPort, Undefined};

struct rte_flow *forward_traffic_to_port(uint16_t port_id,
                                         uint16_t forwarding_port,
                                         struct rte_flow_error *error);

struct rte_flow *send_tag_to_queue(uint16_t port_id, uint16_t queue_id,
                                   uint16_t tag, struct rte_flow_error *error);

struct rte_flow *change_rss_hash(uint16_t port_id, uint16_t nb_queues,
                                 struct rte_flow_error *error);
struct rte_flow *forward_traffic_to_representor(uint16_t port_id,
                                                uint16_t forwarding_port,
                                                enum SRC_OR_DST src_or_dst,
                                                uint16_t port_to_match,
                                                struct rte_flow_error *error);

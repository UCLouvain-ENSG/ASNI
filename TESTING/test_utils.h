#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <stdint.h>
#include <unistd.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 1024
#define NUM_HUGE_MBUFS 2046
#define MBUF_CACHE_SIZE 255
#define NUM_PORTS 1
#define MAX_BURST_SIZE 255

#define MBUF_DATA_SIZE (2048 + 128)
#define HUGE_MBUF_DATA_SIZE (32768 +512) 

#define MAX_NB_CORES 31
#define DMA_MAX_WINDOW 4
#define PORT_TO_WORLD 1
#define PORT_TO_HOST 2

int port_init_testing(uint16_t port, struct rte_mempool *mbuf_pool,
              uint16_t nb_queues,uint16_t ring_size);

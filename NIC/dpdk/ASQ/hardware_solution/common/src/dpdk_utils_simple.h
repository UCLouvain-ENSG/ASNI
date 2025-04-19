#ifndef COMMON_DPDK_UTILS_H_
#define COMMON_DPDK_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_flow.h>
#include <rte_mbuf.h>

#include <doca_error.h>

#include "offload_rules.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RX_RING_SIZE 256 /* RX ring size */
#define TX_RING_SIZE 256 /* TX ring size */
#define NUM_MBUFS                                                              \
    (8 * 1024)              /* Number of mbufs to be allocated in the mempool */
#define MBUF_CACHE_SIZE 250 /* mempool cache size */

struct doca_dev;
struct dpdk_mempool_shadow;
struct doca_buf_inventory;
struct doca_buf;

/*
 * Initialize DPDK environment
 *
 * @argc [in]: number of program command line arguments
 * @argv [in]: program command line arguments
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t dpdk_init(int argc, char **argv);

/*
 * Destroy DPDK environment
 */
void dpdk_fini(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* COMMON_DPDK_UTILS_H_ */

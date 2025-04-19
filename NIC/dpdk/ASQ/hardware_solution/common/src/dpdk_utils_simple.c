

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_sft.h>

#include <doca_buf_inventory.h>
#include <doca_log.h>
#include <doca_mmap.h>

#include "dpdk_utils.h"

#ifdef GPU_SUPPORT
#include "gpu_init.h"
#endif

DOCA_LOG_REGISTER(NUTILS);

#define RSS_KEY_LEN 40
#define MAX_SEGS_BUFFER_SPLIT 8
#define DEFAULT_MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#define MBUF_POOL_NAME_PFX "mb_pool"
uint32_t mbuf_data_size_n = 1;
uint16_t mbuf_data_size[MAX_SEGS_BUFFER_SPLIT] = {DEFAULT_MBUF_DATA_SIZE};

#ifndef IPv6_BYTES
#define IPv6_BYTES_FMT                                                         \
    "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"                                     \
    "%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define IPv6_BYTES(addr)                                                       \
    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],    \
        addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14],    \
        addr[15]
#endif
doca_error_t dpdk_init(int argc, char **argv) {
    int result;

    result = rte_eal_init(argc, argv);
    if (result < 0) {
        DOCA_LOG_ERR("EAL initialization failed");
        return DOCA_ERROR_DRIVER;
    }
    return DOCA_SUCCESS;
}

void dpdk_fini() {
    int result;

    result = rte_eal_cleanup();
    if (result < 0) {
        DOCA_LOG_ERR("rte_eal_cleanup() failed, error=%d", result);
        return;
    }
}

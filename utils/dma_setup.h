#include "asq_descriptors.h"
#include "consts.h"
#include "dma_common.h"
#include "dma_exchange.h"
#include "dma_jobs.h"
#include "dpdk_utils2.h"
#include <doca_argp.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_dpdk.h>
#include <doca_error.h>
#include <doca_log.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

/*Includes for the direct payload transfer*/
#include "mlx5_common.h"
#include "mlx5_common_mr.h"
#include <doca_rdma_bridge.h>

int init_dma_nic(int portid, int nb_core, const char *pcie_addr);

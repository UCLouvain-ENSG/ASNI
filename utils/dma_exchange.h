// #ifdef FAKE_DPDK_MODE_DMA
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// DOCA
#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>

#include <utils.h>

#include "dma_common.h"
#ifdef FAKE_DPDK_MODE_DMA
#include "dma_copy_core.h"
#endif
#include "receive_data_from_host.h"
#include <doca_dma.h>
#include <doca_pe.h>

doca_error_t send_dma_data(char *export_desc, size_t export_desc_len,
                           char *src_buffer, size_t src_buffer_size, char *ip,
                           int port);

/*
 * Saves export descriptor and buffer information content into memory buffers
 *
 * @export_desc_file_path [in]: Export descriptor file path
 * @buffer_info_file_path [in]: Buffer information file path
 * @export_desc [in]: Export descriptor buffer
 * @export_desc_len [in]: Export descriptor buffer length
 * @remote_addr [in]: Remote buffer address
 * @remote_addr_len [in]: Remote buffer total length
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */

doca_error_t receive_dma_data(char *export_desc, size_t *export_desc_len,
                              char **remote_addr, size_t *remote_addr_len,
                              int port);

doca_error_t send_data_to_dpu(char *export_desc, size_t export_desc_len,
                              char *src_buffer, size_t src_buffer_size,
                              int core);

doca_error_t dma_import_memory(const char *pci_addr, char **local_buffer,
                               size_t *local_buffer_size, char **remote_addr,
                               struct dma_resources *resources,
                               struct doca_buf **src_doca_buf,
                               size_t nb_src_doca_buf,
                               struct doca_buf **dst_doca_buf,
                               struct doca_mmap **remote_mmap,
                               struct doca_dma **dma_ctx, int index);

doca_error_t dma_export_memory(char *pci_addr, char *src_buffer,
                               size_t src_buffer_size, int index);
// #endif

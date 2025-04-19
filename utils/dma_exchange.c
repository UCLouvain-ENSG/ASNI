#ifdef FAKE_DPDK_MODE_DMA
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <doca_argp.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>
#include <doca_pe.h>
#include <rte_malloc.h>
#include <utils.h>

#include "common.h"
#include "dma_common.h"
#include "dma_exchange.h"

DOCA_LOG_REGISTER(DMA_EXCHANGE::MAIN);

#define RECV_BUF_SIZE 256 /* Buffer which contains config information */

doca_error_t send_dma_data(char *export_desc, size_t export_desc_len,
                           char *src_buffer, size_t src_buffer_size, char *ip,
                           int port) {
    struct sockaddr_in addr;
    int sock_fd;
    uint64_t buffer_addr = (uintptr_t)src_buffer;
    uint64_t buffer_len = (uint64_t)src_buffer_size;

    char str_buffer_addr[100], str_buffer_len[100];
    sprintf(str_buffer_addr, "%" PRIu64, (uint64_t)buffer_addr);
    sprintf(str_buffer_len, "%" PRIu64, (uint64_t)buffer_len);

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        DOCA_LOG_ERR("Unable to create the socket");
        return DOCA_ERROR_IO_FAILED;
    }

    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    /* Send the descriptor to the DPU */
    int bytes_sent = sendto(sock_fd, export_desc, export_desc_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr));
    if (bytes_sent < 0) {
        close(sock_fd);
        return DOCA_ERROR_IO_FAILED;
    }

    /* Send the buffer data to the DPU */
    bytes_sent = sendto(sock_fd, str_buffer_addr, 100, 0,
                        (struct sockaddr *)&addr, sizeof(addr));
    if (bytes_sent < 0) {
        DOCA_LOG_ERR("Couldn't receive data from host");
        close(sock_fd);
        return DOCA_ERROR_IO_FAILED;
    }

    /* Send the buffer length to the DPU */
    bytes_sent = sendto(sock_fd, str_buffer_len, 100, 0,
                        (struct sockaddr *)&addr, sizeof(addr));
    if (bytes_sent < 0) {
        DOCA_LOG_ERR("Couldn't receive data from host");
        close(sock_fd);
        return DOCA_ERROR_IO_FAILED;
    }

    DOCA_LOG_INFO("buffer_addr : %ld", buffer_addr);
    DOCA_LOG_INFO("buffer_len : %ld", buffer_len);
    DOCA_LOG_INFO("export_desc : %s", export_desc);
    DOCA_LOG_INFO("export_desc_len : %ld", export_desc_len);

    close(sock_fd);
    return DOCA_SUCCESS;
}

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
                              int port) {
    int sock_fd;
    int result;
    char buffer[RECV_BUF_SIZE];

    struct sockaddr_in servaddr, client;

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd == -1) {
        DOCA_LOG_ERR("socket creation failed");
        return DOCA_ERROR_IO_FAILED;
    }

    // servaddr.sin_addr.s_addr = inet_addr("192.168.100.1");
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);

    result = bind(sock_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (result != 0) {
        DOCA_LOG_INFO("Socket bind failed");
        return DOCA_ERROR_IO_FAILED;
    }

    /* Receive the descriptor on the socket */
    socklen_t client_len = sizeof(client);
    *export_desc_len = recvfrom(sock_fd, export_desc, 1024, 0,
                                (struct sockaddr *)&client, &client_len);
    if (*export_desc_len < 0) {
        DOCA_LOG_ERR("Couldn't receive data from host");
        close(sock_fd);
        return DOCA_ERROR_IO_FAILED;
    }
    DOCA_LOG_INFO("export_desc : %s", export_desc);
    DOCA_LOG_INFO("export_desc_len : %ld", *export_desc_len);

    /* Receive the buffer address on the socket */
    int bytes_received = recvfrom(sock_fd, buffer, RECV_BUF_SIZE, 0,
                                  (struct sockaddr *)&client, &client_len);
    if (bytes_received < 0) {
        DOCA_LOG_ERR("Couldn't receive data from host");
        close(sock_fd);
        return DOCA_ERROR_IO_FAILED;
    }
    *remote_addr = (char *)strtoull(buffer, NULL, 0);
    DOCA_LOG_INFO("remote_addr : %lld", strtoull(buffer, NULL, 0));

    memset(buffer, 0, RECV_BUF_SIZE);

    /* Receive the buffer length on the socket */
    bytes_received = recvfrom(sock_fd, buffer, RECV_BUF_SIZE, 0,
                              (struct sockaddr *)&client, &client_len);
    if (bytes_received < 0) {
        DOCA_LOG_ERR("Couldn't receive data from host");
        close(sock_fd);
        return DOCA_ERROR_IO_FAILED;
    }
    *remote_addr_len = strtoull(buffer, NULL, 0);
    DOCA_LOG_INFO("remote_addr_len : %ld", *remote_addr_len);
    DOCA_LOG_INFO("Exported data was received");

    return DOCA_SUCCESS;
}

doca_error_t send_data_to_dpu(char *export_desc, size_t export_desc_len,
                              char *src_buffer, size_t src_buffer_size,
                              int core) {
    struct sockaddr_in addr;
    int sock_fd;
    uint64_t buffer_addr = (uintptr_t)src_buffer;
    uint64_t buffer_len = (uint64_t)src_buffer_size;

    char str_buffer_addr[100], str_buffer_len[100];
    sprintf(str_buffer_addr, "%" PRIu64, (uint64_t)buffer_addr);
    sprintf(str_buffer_len, "%" PRIu64, (uint64_t)buffer_len);

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        DOCA_LOG_ERR("Unable to create the socket");
        return DOCA_ERROR_IO_FAILED;
    }

    addr.sin_addr.s_addr = inet_addr(IP);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT + core);

    /* Send the descriptor to the DPU */
    int bytes_sent = sendto(sock_fd, export_desc, export_desc_len, 0,
                            (struct sockaddr *)&addr, sizeof(addr));
    if (bytes_sent < 0) {
        close(sock_fd);
        return DOCA_ERROR_IO_FAILED;
    }

    /* Send the buffer data to the DPU */
    bytes_sent = sendto(sock_fd, str_buffer_addr, 100, 0,
                        (struct sockaddr *)&addr, sizeof(addr));
    if (bytes_sent < 0) {
        DOCA_LOG_ERR("Couldn't receive data from host");
        close(sock_fd);
        return DOCA_ERROR_IO_FAILED;
    }

    /* Send the buffer length to the DPU */
    bytes_sent = sendto(sock_fd, str_buffer_len, 100, 0,
                        (struct sockaddr *)&addr, sizeof(addr));
    if (bytes_sent < 0) {
        DOCA_LOG_ERR("Couldn't receive data from host");
        close(sock_fd);
        return DOCA_ERROR_IO_FAILED;
    }
    close(sock_fd);
    return DOCA_SUCCESS;
}

doca_error_t dma_import_memory(const char *pci_addr, char **local_buffer,
                               size_t *local_buffer_size, char **remote_addr,
                               struct dma_copy_resources *resources,
                               struct doca_buf **src_doca_buf,
                               size_t nb_src_doca_buf,
                               struct doca_buf **dst_doca_buf,
                               struct doca_mmap **remote_mmap,
                               struct doca_dma **dma_ctx, int index) {
    // struct program_core_objects state = {0};
    // struct doca_event event = {0};
    // struct doca_dma_job_memcpy dma_job_write = {0};
    // struct doca_dma_job_memcpy dma_job_read = {0};
    struct program_core_objects *state = resources->state;
    doca_error_t result;
    char export_desc[1024] = {0};
    *remote_addr = NULL;
    size_t remote_addr_len = 0, export_desc_len = 0;
    /* Create DMA context */
    /* DOCA : Open PCIe device */
    result = allocate_dma_copy_resources(resources);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to allocate DMA copy resources: %s",
                     doca_error_get_descr(result));
        return result;
    }
    state = resources->state;
    result = doca_pe_connect_ctx(state->pe, state->ctx);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to connect progress engine to context: %s",
                     doca_error_get_descr(result));
        goto destroy_resources;
    }
    result = doca_ctx_start(state->ctx);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to start context: %s",
                     doca_error_get_descr(result));
        goto destroy_resources;
    }
    /* DOCA : Receive exported data from host */
    result = receive_data_from_host(export_desc, &export_desc_len, remote_addr,
                                    &remote_addr_len, index);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("receive_data_from_host failed: %s",
                     doca_error_get_descr(result));
        goto destroy_resources;
        return DOCA_ERROR_NOT_CONNECTED;
    }

    /* DOCA : Copy the entire host buffer */
    *local_buffer_size = remote_addr_len;
    //*local_buffer = (char *)rte_malloc(NULL,*local_buffer_size, 0x100000);
    *local_buffer = (char *)aligned_alloc(0x100000, *local_buffer_size);
    if (*local_buffer == NULL) {
        DOCA_LOG_ERR("Failed to allocate buffer memory");
        goto destroy_resources;
    }

    /* DOCA : Populate the mmap */
    result = doca_mmap_set_memrange(state->dst_mmap, *local_buffer,
                                    *local_buffer_size);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to populate buffer memory");
        free(*local_buffer);
        goto destroy_resources;
        return result;
    }
    result = doca_mmap_start(state->dst_mmap);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to start mmap object");
        free(*local_buffer);
        goto destroy_resources;
    }
    /* DOCA : Create a local DOCA mmap from exported data */
    result =
        doca_mmap_create_from_export(NULL, (const void *)export_desc,
                                     export_desc_len, state->dev, remote_mmap);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create mmap from export");
        free(*local_buffer);
        goto destroy_resources;
    }
    /* DOCA : Construct DOCA buffer for each address range */
    result = doca_buf_inventory_buf_get_by_addr(state->buf_inv, *remote_mmap,
                                                *remote_addr, remote_addr_len,
                                                dst_doca_buf);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR(
            "Unable to acquire DOCA buffer representing remote buffer: %s",
            doca_error_get_descr(result));
        doca_mmap_destroy(*remote_mmap);
        goto destroy_resources;
    }
    for (size_t i = 0; i < nb_src_doca_buf; i++) {
        result = doca_buf_inventory_buf_get_by_addr(
            state->buf_inv, state->dst_mmap, *local_buffer, *local_buffer_size,
            &(src_doca_buf[i]));
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR(
                "Unable to acquire DOCA buffer representing local buffer: %s",
                doca_error_get_descr(result));
            doca_buf_dec_refcount(src_doca_buf[i], NULL);
            goto destroy_resources;
        }
    }
    /* DOCA : Construct DOCA buffer for each address range */

    return DOCA_SUCCESS;
destroy_resources:
    doca_error_t tmp_result = destroy_dma_resources(resources);
    if (tmp_result != DOCA_SUCCESS) {
        DOCA_ERROR_PROPAGATE(result, tmp_result);
        DOCA_LOG_ERR("Failed to destroy DMA resources: %s",
                     doca_error_get_descr(tmp_result));
    }

    return result;
}

doca_error_t dma_export_memory(char *pci_addr, char *src_buffer,
                               size_t src_buffer_size, int index) {
    doca_error_t result;
    char *export_desc;
    size_t export_desc_len = 0;
    struct dma_copy_resources resources;
    struct program_core_objects *state = &resources.state;
    result = allocate_dma_host_resources(pci_addr, state);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to allocate DMA host resources: %s",
                     doca_error_get_descr(result));
        return result;
    }
    /* Allow exporting the mmap to DPU for read only operations */
    result = doca_mmap_set_permissions(state->src_mmap,
                                       DOCA_ACCESS_FLAG_PCI_READ_WRITE);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set mmap permissions: %s",
                     doca_error_get_descr(result));
        goto destroy_resources;
    }
    /* Populate the memory map with the allocated memory */
    result =
        doca_mmap_set_memrange(state->src_mmap, src_buffer, src_buffer_size);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set memory range for source mmap: %s",
                     doca_error_get_descr(result));
        goto destroy_resources;
    }
    result = doca_mmap_start(state->src_mmap);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to start source mmap: %s",
                     doca_error_get_descr(result));
        goto destroy_resources;
    }
    /* DOCA : Export DOCA mmap to enable DMA on Host*/
    result =
        doca_mmap_export_pci(state->src_mmap, state->dev,
                             (const void **)&export_desc, &export_desc_len);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to start export source mmap: %s",
                     doca_error_get_descr(result));
        goto destroy_resources;
    }

    /* DOCA : Send exported string and wait for ack that DMA was done on
     * receiver node */
    result = send_data_to_dpu(export_desc, export_desc_len, src_buffer,
                              src_buffer_size, index);
    if (result != DOCA_SUCCESS) {
        printf("send failed\n");
        goto destroy_resources;
        free(export_desc);
        return DOCA_ERROR_NOT_CONNECTED;
    }
    return result;

destroy_resources:
    doca_error_t tmp_result = destroy_dma_host_resources(state);
    if (tmp_result != DOCA_SUCCESS) {
        DOCA_ERROR_PROPAGATE(result, tmp_result);
        DOCA_LOG_ERR("Failed to destroy DMA host resources: %s",
                     doca_error_get_descr(tmp_result));
    }
    return result;
}
#endif

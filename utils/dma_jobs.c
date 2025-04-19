#ifdef FAKE_DPDK_MODE_DMA
#include <stdint.h>
#include <string.h>

#include "dma_common.h"
#include "dma_jobs.h"
#include <arpa/inet.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>
#include <doca_pe.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

DOCA_LOG_REGISTER(DMA_JOB_UTILS)

void set_buf_write(struct doca_buf *src_doca_buf, struct doca_buf *dst_doca_buf,
                   void *dst, void *src, size_t size) {
    doca_error_t result;

    /* DOCA : Set data position in src_buff */
    result = doca_buf_set_data(dst_doca_buf, dst, size);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set data for DOCA src buffer: %s",
                     doca_error_get_descr(result));
    }

    result = doca_buf_set_data(src_doca_buf, src, size);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set data for DOCA dst buffer: %s",
                     doca_error_get_descr(result));
    }
}

void set_buf_read(struct doca_buf *src_doca_buf, struct doca_buf *dst_doca_buf,
                  void *src, void *dst, size_t size) {
    doca_error_t result;

    /* DOCA : Set data position in src_buff */
    result = doca_buf_set_data(src_doca_buf, dst, size);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set data for DOCA src buffer: %s",
                     doca_error_get_descr(result));
    }

    result = doca_buf_set_data(dst_doca_buf, src, size);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set data for DOCA dst buffer: %s",
                     doca_error_get_descr(result));
    }
}

doca_error_t read_write(struct doca_dma_task_memcpy *dma_task,
                        struct program_core_objects *state,
                        struct timespec ts) {
    doca_error_t result;
    struct doca_task *task;
    task = doca_dma_task_memcpy_as_task(dma_task);
    /* DOCA : Enqueue DMA job */
    result = doca_task_submit(task);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to submit DMA task: %s",
                     doca_error_get_descr(result));
        doca_task_free(task);
        return result;
    }
    resources.run_pe_progress = true;
    /* Wait for all tasks to be completed and context stopped */
    while (resources.run_pe_progress) {
        if (doca_pe_progress(state->pe) == 0) {
            nanosleep(&ts, &ts);
        }
    }
    return DOCA_SUCCESS;
}

doca_error_t submit_async(struct doca_dma_job_memcpy dma_job,
                          struct program_core_objects *state) {
    doca_error_t result;
    /* DOCA : Enqueue DMA job */
    result = doca_workq_submit(state->workq, &dma_job.base);
    while (result == DOCA_ERROR_NO_MEMORY) {
        printf("inside error\n");
        result = doca_workq_submit(state->workq, &dma_job.base);
    }
    return DOCA_SUCCESS;
}

doca_error_t wait_on_jobs(dma_job_struct_t *jobs, int nb_jobs) {
    uint8_t active_jobs[nb_jobs];
    memset(active_jobs, 0, nb_jobs * sizeof(uint8_t));
    doca_error_t result;
    int remaining_jobs = nb_jobs;
    struct doca_event event;
    while (remaining_jobs > 0) {
        // printf("waiting for jobs\n");
        for (int i = 0; i < nb_jobs; i++) {
            if (active_jobs[i] == 0) {
                if ((result = doca_workq_progress_retrieve(
                         (jobs[i].state)->workq, &event,
                         DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) != DOCA_ERROR_AGAIN) {
                    if (result == DOCA_SUCCESS) {
                        result = (doca_error_t)event.result.u64;
                        if (result != DOCA_SUCCESS) {
                            DOCA_LOG_ERR("DMA job event returned
                                         unsuccessfully
                                         : % s ",
                                               doca_error_get_descr(result));
                            return result;
                        } else {
                            active_jobs[i] = -1;
                            remaining_jobs--;
                        }
                    } else {
                        DOCA_LOG_ERR("Failed to retrieve DMA job: %s",
                                     doca_error_get_descr(result));
                        return result;
                    }
                }
            }
        }
    }
    return DOCA_SUCCESS;
}

doca_error_t set_buffers_and_submit_job(struct program_core_objects *state,
                                        struct doca_buf *src_doca_buf,
                                        char *src_buf,
                                        struct doca_buf *dst_doca_buf,
                                        char *dst_buffer, size_t buffer_size) {
    struct doca_event event = {0};
    struct timespec ts = {0};
    struct doca_dma_job_memcpy dma_job = {0};

    dma_job.base.type = DOCA_DMA_JOB_MEMCPY;
    dma_job.base.flags = DOCA_JOB_FLAGS_NONE;
    dma_job.base.ctx = state->ctx;
    dma_job.dst_buff = dst_doca_buf;
    dma_job.src_buff = src_doca_buf;
    // printf("buffer_size : %d\n", buffer_size);
    doca_error_t result;
    result = doca_buf_set_data(dst_doca_buf, dst_buffer, buffer_size);

    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set data for DOCA buffer1: %s",
                     doca_error_get_descr(result));
        return result;
    }
    result = doca_buf_set_data(src_doca_buf, src_buf, buffer_size);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set data for DOCA buffer2: %s",
                     doca_error_get_descr(result));
        return result;
    }
    return read_write(dma_job, state, ts, event);
}

doca_error_t set_buffers_and_submit_job_async(dma_job_struct_t *job) {
    struct program_core_objects *state = job->state;
    struct doca_buf *src_doca_buf = job->src_doca_buf;
    char *src_buf = job->src_buf;
    struct doca_buf *dst_doca_buf = job->dst_doca_buf;
    char *dst_buffer = job->dst_buffer;
    size_t buffer_size = job->buffer_size;
    struct doca_dma_job_memcpy dma_job = {0};
    // printf("buffer_size = %d\n", buffer_size);
    dma_job.base.type = DOCA_DMA_JOB_MEMCPY;
    dma_job.base.flags = DOCA_JOB_FLAGS_NONE;
    dma_job.base.ctx = state->ctx;
    dma_job.dst_buff = dst_doca_buf;
    dma_job.src_buff = src_doca_buf;
    // printf("buffer_size : %d\n", buffer_size);
    doca_error_t result;
    result = doca_buf_set_data(dst_doca_buf, dst_buffer, buffer_size);

    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set data for DOCA buffer1: %s",
                     doca_error_get_descr(result));
        return result;
    }
    result = doca_buf_set_data(src_doca_buf, src_buf, buffer_size);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set data for DOCA buffer2: %s",
                     doca_error_get_descr(result));
        return result;
    }
    return submit_async(dma_job, state);
}

doca_error_t set_buffers_and_submit_job_sync(dma_job_struct_t *job) {
    struct program_core_objects *state = job->state;
    struct doca_buf *src_doca_buf = job->src_doca_buf;
    char *src_buf = job->src_buf;
    struct doca_buf *dst_doca_buf = job->dst_doca_buf;
    char *dst_buffer = job->dst_buffer;
    size_t buffer_size = job->buffer_size;
    struct timespec ts = {0};
    struct doca_dma_job_memcpy dma_job = {0};
    // printf("buffer_size = %d\n", buffer_size);
    dma_job.base.type = DOCA_DMA_JOB_MEMCPY;
    dma_job.base.flags = DOCA_JOB_FLAGS_NONE;
    dma_job.base.ctx = state->ctx;
    dma_job.dst_buff = dst_doca_buf;
    dma_job.src_buff = src_doca_buf;
    // printf("buffer_size : %d\n", buffer_size);
    doca_error_t result;
    result = doca_buf_set_data(dst_doca_buf, dst_buffer, buffer_size);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set data for DOCA buffer1: %s",
                     doca_error_get_descr(result));
        return result;
    }
    result = doca_buf_set_data(src_doca_buf, src_buf, buffer_size);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set data for DOCA buffer2: %s",
                     doca_error_get_descr(result));
        return result;
    }
    return read_write(dma_job, state, ts);
};

doca_error_t submit_job_sync(struct program_core_objects *state,
                             struct doca_buf *src_doca_buf,
                             struct doca_buf *dst_doca_buf) {
    struct doca_dma_job_memcpy dma_job = {0};
    // printf("buffer_size = %d\n", buffer_size);
    dma_job.base.type = DOCA_DMA_JOB_MEMCPY;
    dma_job.base.flags = DOCA_JOB_FLAGS_NONE;
    dma_job.base.ctx = state->ctx;
    dma_job.dst_buff = dst_doca_buf;
    dma_job.src_buff = src_doca_buf;
    struct doca_event event = {0};
    struct timespec ts = {0};
    // printf("buffer_size : %d\n", buffer_size);
    return read_write(dma_job, state, ts, event);
};
#endif

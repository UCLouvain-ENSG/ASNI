#ifdef FAKE_DPDK_MODE_DMA
#include <doca_error.h>
//
//
// typedef struct
// {
//     struct program_core_objects *state;
//     struct doca_buf *src_doca_buf;
//     char *src_buf;
//     struct doca_buf *dst_doca_buf;
//     char *dst_buffer;
//     size_t buffer_size;
// } dma_job_struct_t;
//
// //doca_error_t read_write(struct doca_dma_job_memcpy dma_job, struct
// program_core_objects *state, struct timespec ts, struct doca_event event);
// doca_error_t
// set_buffers_and_submit_job(struct program_core_objects *state,
//                            struct doca_buf *src_doca_buf,
//                            char *src_buf,
//                            struct doca_buf *dst_doca_buf,
//                            char *dst_buffer,
//                            size_t buffer_size);
//
// //void set_buf_read(struct doca_buf *src_doca_buf, struct doca_buf
// *dst_doca_buf, void *src, void *dst, size_t size); doca_error_t
// set_buffers_and_submit_job_sync(dma_job_struct_t *job);
// doca_error_t
// set_buffers_and_submit_job_async(dma_job_struct_t *job);
//
// doca_error_t wait_on_jobs(dma_job_struct_t *jobs, int nb_jobs);
//
// doca_error_t
// submit_job_sync(struct program_core_objects *state,
//                 struct doca_buf *src_doca_buf,
//                 struct doca_buf *dst_doca_buf);
//
// doca_error_t
// submit_async(struct doca_dma_job_memcpy dma_job, struct program_core_objects
// *state);
#endif

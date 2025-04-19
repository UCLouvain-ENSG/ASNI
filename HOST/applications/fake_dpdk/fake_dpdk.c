#include "fake_dpdk.h"
#include "asq_descriptors.h"
void fake_dpdk_init(int argc, char **argv, uint8_t nb_core, uint8_t burst_size,
                    int (*app)(void *), volatile bool *force_quit) {
    fake_state.force_quit = force_quit;
    printf("Initializing fake DPDK\n");

#if defined(FAKE_DPDK_MODE_XCHG_ASNI) || defined(FAKE_DPDK_MODE_XCHG)
    fake_state.underlying_state = xchg_init(argc, argv);
    xchg_run(&fake_state, app);
#endif

#ifdef FAKE_DPDK_MODE_DMA
    fake_state.underlying_state =
        stable_dma_dpdk_init(argc, argv, nb_core, burst_size);
    // Run the application
#ifndef FAKE_DPDK_BURST_MODE
    (*app)(&fake_state);
    stable_dma_dpdk_free(
        (struct stable_dma_dpdk_dma_state *)fake_state.underlying_state);
#endif /* ifndef FAKE_DPDK_BURST_MODE */
#endif
#if defined FAKE_DPDK_MODE_DPDK_ASQ ||                                         \
    defined FAKE_DPDK_MODE_DPDK_ASQ_HW_DP ||                                   \
    defined FAKE_DPDK_MODE_DPDK_ASQ_HW_DD
    fake_state.underlying_state = asq_init(argc, argv);
    asq_run(&fake_state, app);
#endif
#ifdef FAKE_DPDK_MODE_DPDK_ASQ_DPT
    fake_state.underlying_state = asq_init_dpt(argc, argv);
    asq_run(&fake_state, app);
#endif

#ifdef FAKE_DPDK_MODE_DPDK_BASELINE
    fake_state.underlying_state = baseline_init(argc, argv);
    baseline_run(&fake_state, app);
#endif
}


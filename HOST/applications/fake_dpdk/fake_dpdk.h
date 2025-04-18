#pragma once
#include "asni_descriptors.h"
#include <rte_version.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
/* In order to optimally use the fake_dpdk, you need to define which underlying
   architecture you want to use. To do so, you need to define one of the
   following flags:

    ASNI_MODE_DMA : Use the DMA mode
    ASNI_MODE_DPDK_DD : Use the DPDK mode that aligns every descriptors and
   then payload
   ASNI_MODE_DPDK_DP : Use the DPDK mode that interleaves
   descriptors and payload
   ASNI_MODE_DOCA : Use the DOCA flow mode

    Once you defined the underlying architecture, you must specify what
   information must go through the descriptors :

    ASNI_DESC_IP_SRC : The source IP address
    ASNI_DESC_IP_DST : The destination IP address
    ASNI_DESC_TIMESTAMP : The timestamp of the packet
    ASNI_DESC_SIZE : The length of the descriptor in bytes
*/
#define BURST_SIZE 32

#include "asni.h"
#if defined(ASNI_MODE_XCHG_ASNI) || defined(ASNI_MODE_XCHG)
#if RTE_VERSION <= RTE_VERSION_NUM(23, 11, 0, 0)
#include "xchg_ver.h"
#else
#include "xchg_ver23.h"
#endif
#endif
#ifdef ASNI_MODE_DMA
#include "stable_dma_dpdk.h"
#elif defined ASNI_MODE || defined ASNI_MODE_HW_DP ||                          \
    defined ASNI_MODE_HW_DD || defined ASNI_MODE_DPT
#include "asni.h"
#elif defined ASNI_MODE_DPDK_BASELINE
#include "baseline.h"
#endif

// A Quick flag to enable the five tuple within the descriptors
#ifdef ASNI_DESC_FIVE_TUPLE

#define ASNI_DESC_IP_SRC
#define ASNI_DESC_IP_DST
#define ASNI_DESC_PORT_DST
#define ASNI_DESC_PORT_SRC
#define ASNI_DESC_IP_PROTO

#endif

/**
 * @brief struct hiding the underlying architecture, passed by the application
 * to the fake_dpdk implementation to allow underlying stateful operations
 */
struct fake_dpdk_state {
  void *underlying_state;
  volatile bool *force_quit;
};
struct fake_dpdk_state fake_state;

/**
 * @brief Initializes fake_dpdk environment.
 *
 * @param argc [in]: command line arguments size
 * @param argv [in]: array of command line arguments
 * @param nb_core [in]: number of cores to use
 * @param burst_size [in]: burst size to use
 * @param app [in]: function ptr towards the application to run
 * @param force_quit [in]: pointer to a boolean that will be set to true when
 * the application must quit
 */
void fake_dpdk_init(int argc, char **argv, uint8_t nb_core, uint8_t burst_size,
                    int (*app)(void *), volatile bool *force_quit);

#ifdef ASNI_MODE_DMA
#define ASNI_FOR_EACH_PACKET(descriptor)                                       \
  STABLE_DMA_DPDK_FOR_EACH_PACKET(fake_state.underlying_state, descriptor,     \
                                  fake_state.force_quit)
#define ASNI_FOR_EACH_PACKET_END() STABLE_DMA_DPDK_FOR_EACH_PACKET_END()
#define ASNI_RX_BURST(buffers, nb_desc)                                        \
  STABLE_DMA_DPDK_RX_BURST(fake_state.underlying_state, buffers, nb_desc)
#define ASNI_GET_BURST_SIZE()                                                  \
  STABLE_DMA_DPDK_GET_BURST_SIZE(fake_state.underlying_state)
#endif
#if (defined(ASNI_MODE) || defined(ASNI_MODE_DPT) ||                           \
     defined(ASNI_MODE_HW_DD)) &&                                              \
    ((!defined(ASNI_MODE_DP) && !defined(ASNI_MODE_PP) &&                      \
      !defined(ASNI_MODE_PP_EXP_DESC)))
#define ASNI_FOR_EACH_PACKET(descriptor)                                       \
  ASNI_FOR_EACH_PACKET_DP(fake_state.underlying_state, descriptor,             \
                          fake_state.force_quit)
#define ASNI_FOR_EACH_PACKET_END() ASNI_FOR_EACH_PACKET_DP_END()

#endif
#if defined(ASNI_MODE_PP)
#define ASNI_FOR_EACH_PACKET(descriptor)                                       \
  ASNI_FOR_EACH_PACKET_PP(fake_state.underlying_state, descriptor,             \
                          fake_state.force_quit)
#define ASNI_FOR_EACH_PACKET_END() ASNI_FOR_EACH_PACKET_PP_END()
#endif
#if defined(ASNI_MODE_PP_EXP_DESC)
#define ASNI_FOR_EACH_PACKET(descriptor)                                       \
  ASNI_FOR_EACH_PACKET_PP_EXP_DESC(fake_state.underlying_state, descriptor,    \
                                   fake_state.force_quit)
#define ASNI_FOR_EACH_PACKET_END() ASNI_FOR_EACH_PACKET_PP_EXP_DESC_END()
#endif

#if defined(ASNI_MODE_HW_DP) || defined(ASNI_MODE_DP)
#define ASNI_FOR_EACH_PACKET(descriptor)                                       \
  ASNI_HW_DP_FOR_EACH_PACKET(fake_state.underlying_state, descriptor,          \
                             fake_state.force_quit)
#define ASNI_FOR_EACH_PACKET_END() ASNI_HW_DP_FOR_EACH_PACKET_END()
#endif

#ifdef ASNI_MODE_XCHG
#define ASNI_FOR_EACH_PACKET(descriptor)                                       \
  XCHG_FOR_EACH_PACKET(fake_state.underlying_state, descriptor,                \
                       fake_state.force_quit)
#define ASNI_FOR_EACH_PACKET_END() XCHG_FOR_EACH_PACKET_END()
#endif

#ifdef ASNI_MODE_XCHG_ASNI
#define ASNI_FOR_EACH_PACKET(descriptor)                                       \
  XCHG_ASNI_FOR_EACH_PACKET(fake_state.underlying_state, descriptor,           \
                            fake_state.force_quit)
#define ASNI_FOR_EACH_PACKET_END() XCHG_ASNI_FOR_EACH_PACKET_END()
#endif

#ifdef ASNI_MODE_DPDK_BASELINE
#define ASNI_FOR_EACH_PACKET(descriptor)                                       \
  BASELINE_FOR_EACH_PACKET(fake_state.underlying_state, descriptor,            \
                           fake_state.force_quit)
#define ASNI_FOR_EACH_PACKET_END() BASELINE_FOR_EACH_PACKET_END()
#endif

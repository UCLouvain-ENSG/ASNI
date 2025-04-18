NO_MBUF_XCHG=1

ifeq ($(RTE_SDK),)
	$(error "Please define RTE_SDK environment variable")
endif

include $(RTE_SDK)/mk/rte.vars.mk

APP = server

ifeq ($(CYCLES),1)
APP := $(APP)-cycles
CFLAGS += -DHAVE_CYCLE=1
endif


ifeq ($(VER),minimal)
APP := $(APP)-minimal
CFLAGS += -DHAVE_MINIMAL=1
endif


ifeq ($(NOCQE),1)
APP := $(APP)-nocqe
CFLAGS += -DHAVE_NOCQE=1
endif

ifeq ($(RTC),1)
APP := $(APP)-rtc
CFLAGS += -DHAVE_RTC=1
endif


CFLAGS += -gdwarf

# all source are stored in SRCS-y
SRCS-y := server.c xchg.c ../../../utils/MACaddress.c


# Default target, detect a build directory, by looking for a path with a .config
RTE_TARGET ?= $(notdir $(abspath $(dir $(firstword $(wildcard $(RTE_SDK)/*/.config)))))


ifeq (${CONFIG_RTE_XCHG_MBUF},y})
$(error "This example cannot be built with XCHG_MBUF enabled.")
endif
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS) -Wno-unused-parameter
# Add flag to allow experimental API as l2fwd uses rte_ethdev_set_ptype API
CFLAGS += -DALLOW_EXPERIMENTAL_API

include $(RTE_SDK)/mk/rte.extapp.mk

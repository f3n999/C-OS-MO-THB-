MODULE ?= kmon


obj-m += $(MODULE).o


EXTRA_CFLAGS += -I$(PWD)/include


ifeq ($(NO_PLUGINS),1)
KBUILD_ARGS := GCC_PLUGINS_CFLAGS=
endif

.PHONY: all clean
all:
        $(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) $(KBUILD_ARGS) modules

clean:
        $(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
        $(RM) -r *.o *.ko *.mod *.mod.c .*.cmd *.symvers Module.symvers modules.order .tmp_versions

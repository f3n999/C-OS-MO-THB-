# Makefile — module noyau "kmon" (out-of-tree)

obj-m       += kmon.o
kmon-objs   := src/kmon.o

# Si tu as des headers locaux
EXTRA_CFLAGS += -I$(PWD)/include

# Contourner les plugins GCC (Alpine, etc.) si besoin: make NO_PLUGINS=1
ifeq ($(NO_PLUGINS),1)
KBUILD_ARGS := GCC_PLUGINS_CFLAGS=
endif

.PHONY: all clean
all:
	@echo "==> Build module pour $(shell uname -r)"
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) $(KBUILD_ARGS) modules

clean:
	@echo "==> Clean"
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	$(RM) -r *.o *.ko *.mod *.mod.c .*.cmd *.symvers Module.symvers modules.order .tmp_versions

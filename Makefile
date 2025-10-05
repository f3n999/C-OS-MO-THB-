# This Makefile is used to build the kmon kernel module.

# The name of the module object file.
# The 'obj-m' variable tells the kernel build system to build kmon.o as a loadable module.
obj-m := kmon.o

# The source file(s) for the kmon module.
# The build system will compile kmon.c to produce kmon.o.
kmon-objs := src/kmon.o

# Kernel-specific build flags.
# -Werror: Treat all warnings as errors. This enforces a high standard of code quality.
# -Wall: Enable all standard compiler warnings.
# -Wextra: Enable extra compiler warnings beyond -Wall.
# -std=c99: Use the C99 standard for compilation.
# -g: Include debugging information.
# -fno-pie: Disable Position-Independent Executable generation, which can be problematic for kernel modules.
EXTRA_CFLAGS := -g -Wall -Wextra -Werror -pedantic -std=c99 -fno-pie

# The directory where the kernel headers and build system are located.
# `uname -r` gets the current running kernel version.
KDIR := /lib/modules/$(shell uname -r)/build

# Default target. This is what 'make' will do if no specific target is given.
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Target to clean up the build directory.
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Target to load the module into the kernel.
# Requires root privileges.
load: all
	@echo "  LOADING kernel module kmon.ko..."
	sudo insmod ./kmon.ko
	@echo "  Module loaded. Use 'dmesg' to see kernel messages and 'lsmod | grep kmon' to verify."

# Target to unload the module from the kernel.
# Requires root privileges.
unload:
	@echo "  UNLOADING kernel module kmon..."
	sudo rmmod kmon
	@echo "  Module unloaded."

# Declare phony targets to prevent conflicts with files of the same name.
.PHONY: all clean load unload
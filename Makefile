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

# Cibles pour les outils en espace utilisateur
TOOLS   := tools/kmon_trigger tools/kmonctl
CFLAGS_tools := -O2 -Wall

tools: $(TOOLS)

tools/kmon_trigger: tools/kmon_trigger.c
	$(CC) $(CFLAGS_tools) -o $@ $<

tools/kmonctl: tools/kmonctl.c
	$(CC) $(CFLAGS_tools) -o $@ $<

# Cible pour installer le module dans le répertoire des modules du système
install:
	install -D -m0644 kmon.ko /lib/modules/$(shell uname -r)/extra/kmon.ko
	depmod -a

# Cible pour configurer la persistance au démarrage et la journalisation
persist: all install enable-boot enable-options enable-logs

enable-boot:
	@echo "kmon" > /etc/modules-load.d/kmon.conf
	@echo "[enable-boot] kmon sera chargé au boot"

# Paramètres par défaut pour le module
MODULE_MATCH ?= "passwd,shadow"
MODULE_SYM   ?= "__x64_sys_openat"

enable-options:
	@echo 'options kmon match=$(MODULE_MATCH) sym=$(MODULE_SYM)' > /etc/modprobe.d/kmon.conf
	@echo "[enable-options] /etc/modprobe.d/kmon.conf -> match=$(MODULE_MATCH) sym=$(MODULE_SYM)"

enable-logs:
	@mkdir -p /etc/rsyslog.d
	@printf ':msg, contains, "kmon:" -/var/log/kmon.log\\n& stop\\n' > /etc/rsyslog.d/50-kmon.conf
	@echo "[enable-logs] /var/log/kmon.log recevra les lignes 'kmon:'"

.PHONY: all clean tools install persist enable-boot enable-options enable-logs
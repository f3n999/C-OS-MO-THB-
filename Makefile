# Makefile racine (out-of-tree)
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

obj-m += kmon.o
kmon-y := src/kmon.o

# CFLAGS pour notre module
# -Werror: Traite tous les avertissements comme des erreurs.
# -Wall: Active la plupart des avertissements.
# -Wextra: Active des avertissements supplémentaires.
# -pedantic: Exige une conformité stricte à la norme C.
# -std=c99: Utilise la norme C99.
# -g: Inclut les informations de débogage.
# -fno-pie: Désactive la génération de code indépendant de la position (PIE), souvent nécessaire pour les modules noyau.
EXTRA_CFLAGS := -g -Wall -Wextra -Werror -pedantic -std=c99 -fno-pie

# Cible par défaut pour compiler le module
all: modules
modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Cible pour nettoyer les fichiers générés
clean:
	@echo "  CLEANING up build files..."
	make -C $(KDIR) M=$(PWD) clean
	$(RM) tools/kmon_trigger tools/kmonctl

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
# ==== Kbuild wrapper + Kbuild rules (un seul fichier) =========================
# Utilisation :
#   make              # construit kmon.ko
#   make clean        # nettoie
#   make load         # insmod (essaie openat puis fallback openat2)
#   make unload       # rmmod
#   make install      # installe le .ko dans /lib/modules/.../extra + depmod
#
# Variables utiles (optionnelles) :
#   KDIR=/chemin/vers/headers      # si /lib/modules/$(uname -r)/build n’existe pas
#   CC=clang LLVM=1 LLVM_IAS=1     # si tu veux clanger
#
# Remarques :
# - On force GCC_PLUGINS_CFLAGS= vide pour éviter les plugins GCC foireux (Alpine).
# - NE PAS forcer -std=c99 etc. Le noyau gère ses propres flags.
# ============================================================================

# ---------- Partie Kbuild (appelée par le noyau) ----------
ifneq ($(KERNELRELEASE),)

# Déclare le module à construire : kmon.ko à partir de src/kmon.c
obj-m    += kmon.o
kmon-y   := src/kmon.o

# Tu peux placer ici des warning-tweaks sûrs côté kernel si besoin :
# ccflags-y += -Wno-maybe-uninitialized

else
# ---------- Partie "wrapper" (appelée par l’utilisateur) ----------
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# Affiche un message propre si les headers ne sont pas là
define _no_headers
	@echo "ERROR: headers noyau introuvables pour $$(uname -r) :" 1>&2 ; \
	echo " - $(KDIR) n'existe pas." 1>&2 ; \
	echo "Installe d'abord les headers :" 1>&2 ; \
	echo "  Debian/Ubuntu/Kali : sudo apt update && sudo apt install linux-headers-$$(uname -r) || sudo apt install linux-headers-amd64" 1>&2 ; \
	echo "  Alpine :             sudo apk add --no-cache linux-virt-dev build-base" 1>&2 ; \
	exit 2
endef

.PHONY: all modules clean load unload install reinstall

all: modules
modules:
	@if [ ! -e "$(KDIR)/Makefile" ]; then $(call _no_headers); fi
	@echo "[build] KDIR=$(KDIR)"
	$$(MAKE) -C "$(KDIR)" M="$(PWD)" \
		GCC_PLUGINS_CFLAGS= \
		CC="$(CC)" LLVM="$(LLVM)" LLVM_IAS="$(LLVM_IAS)" \
		modules

clean:
	-@$(MAKE) -C "$(KDIR)" M="$(PWD)" clean >/dev/null 2>&1 || true
	@rm -rf .tmp_versions Module.symvers modules.order \
	        kmon.mod kmon.mod.c kmon.mod.o kmon.o kmon.ko \
	        .*.cmd *.o *.ko *.mod *.mod.c

# Charge le module avec paramètres par défaut (openat -> fallback openat2)
load: modules
	-@sudo rmmod kmon 2>/dev/null || true
	@sudo insmod ./kmon.ko match="passwd,shadow" 2>/dev/null || \
	 sudo insmod ./kmon.ko match="passwd,shadow" sym="__x64_sys_openat2"
	@echo "[ok] kmon chargé. Paramètres actuels:"
	@-cat /sys/module/kmon/parameters/match 2>/dev/null || true
	@-cat /sys/module/kmon/parameters/sym   2>/dev/null || true

unload:
	@sudo rmmod kmon && echo "[ok] kmon déchargé" || echo "[info] déjà déchargé ?"

install: modules
	@sudo install -D -m0644 ./kmon.ko /lib/modules/$$(uname -r)/extra/kmon.ko
	@sudo depmod -a
	@echo "[ok] installé -> /lib/modules/$$(uname -r)/extra/kmon.ko (pense à modprobe kmon)"

reinstall: unload clean all install

endif

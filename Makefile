# Nom de l'objet principal du module
obj-m := kmon.o

# Flags de compilation stricts imposés
# -Wextra: Active des avertissements supplémentaires.
# -Werror: Traite tous les avertissements comme des erreurs. La compilation échoue au moindre warning.
# -fanalyzer: Active l'analyseur statique de GCC pour détecter des problèmes logiques.
# -pedantic: Exige une conformité stricte à la norme C.
# -std=c99: Utilise la norme C99.
EXTRA_CFLAGS := -Wextra -Werror -fanalyzer -pedantic -std=c99 -I$(src)/include

# Cible par défaut pour compiler le module
all:
	@echo "  COMPILING a kernel module..."
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	@echo "  SUCCESS"

# Cible pour nettoyer les fichiers générés
clean:
	@echo "  CLEANING up build files..."
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	@echo "  DONE"

# Cibles pour charger et décharger le module (nécessite les droits root)
load: all
	@echo "  LOADING kernel module kmon.ko..."
	sudo insmod ./kmon.ko
	@echo "  Module loaded. Use 'lsmod | grep kmon' to verify."

unload:
	@echo "  UNLOADING kernel module kmon..."
	sudo rmmod kmon
	@echo "  Module unloaded."

# Déclare les cibles qui ne sont pas des fichiers
.PHONY: all clean load unload
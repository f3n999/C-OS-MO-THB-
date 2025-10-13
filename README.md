# Projet de Module Noyau Linux : Surveillance d'Appels Système

Ce projet est réalisé dans le cadre du cours de Système d'Exploitation de Hugo Chassaing et Julien Palard.

## Description

L'objectif est de développer un module noyau pour Linux capable de surveiller et de logger les appels système `openat` effectués sur des fichiers sensibles.

## 1) Pré-requis

### Alpine Linux (environnement de test)

```sh
# outils de build + en-têtes du noyau courant
sudo apk add --no-cache git build-base linux-headers elfutils-dev rsyslog
```

### Debian/Ubuntu (au cas où)

```bash
sudo apt-get update
sudo apt-get install -y git build-essential linux-headers-$(uname -r) rsyslog
```

> **Pourquoi ?** `linux-headers-$(uname -r)` fournit l’arborescence `/lib/modules/<version>/build` que le Makefile utilise pour compiler votre module contre **le noyau en cours d’exécution**.

---

## 2) Cloner le projet

```bash
git clone https://github.com/f3n999/C-OS-MO-THB-.git
cd C-OS-MO-THB-
```

---

## 3) Compiler

Le Makefile appelle automatiquement `make -C /lib/modules/$(uname -r)/build M=$(PWD) modules`.

```bash
make clean          # (optionnel) remet à zéro
make                # construit kmon.ko
```

Tu dois voir à la fin un fichier `kmon.ko` à la racine du projet.

> **Avertissements** :
> - `warning: the compiler differs from the one used to build the kernel`: C'est normal sur certains environnements comme Alpine.
> - `module verification failed: signature…`: C'est également normal si la signature de modules n'est pas imposée sur le système.

---

## 4) Charger le module à la main (test rapide)

Deux paramètres principaux :

*   `match`: Une chaîne de caractères contenant les noms de fichiers à surveiller, séparés par des virgules (ex: `"passwd,shadow"`).
*   `sym`: Le symbole du syscall à intercepter (ex: `__x64_sys_openat` ou `__x64_sys_openat2`).

### Vérifier quel symbole `openat` est disponible

```bash
grep -E "__x64_sys_openat2|__x64_sys_openat" /proc/kallsyms | head
```

### Charger le module

```bash
# Essayer avec le symbole le plus récent d'abord
sudo insmod ./kmon.ko match="passwd,shadow,group,hosts" sym="__x64_sys_openat2" 2>/dev/null || \
sudo insmod ./kmon.ko match="passwd,shadow,group,hosts" sym="__x64_sys_openat"
```

> Si vous obtenez `insmod: ERROR: could not insert module ...: File exists`, cela signifie que le module est déjà chargé.

### Vérifier l'état du module

```bash
# Vérifier que le module est chargé
lsmod | grep kmon

# Vérifier les paramètres actuels
cat /sys/module/kmon/parameters/match
cat /sys/module/kmon/parameters/sym

# Voir les derniers messages du noyau
dmesg | tail -n 20 | grep -i kmon
```

---

## 5) Voir les logs

Le module écrit ses logs dans le ring buffer du noyau.

### Déclencher un événement de test

```bash
# Cet outil tente d'ouvrir /etc/passwd et /etc/shadow
./tools/kmon_trigger

# Ou manuellement
cat /etc/passwd > /dev/null
sudo cat /etc/shadow > /dev/null # Nécessite sudo pour réussir, mais l'accès est tracé même sans
```

### Consulter les logs

```bash
# Affiche les logs en temps réel
sudo dmesg -w | grep --line-buffered "kmon:"

# Ou, si configuré (voir étape 6), voir le fichier de log dédié
tail -f /var/log/kmon.log
```

---

## 6) (Optionnel) Rendre l’usage « confortable » (Installation & Persistance)

Le `Makefile` inclut des cibles pour automatiser l'installation et la configuration.

**Actions de la cible `persist` :**
*   Installe `kmon.ko` dans `/lib/modules/$(uname -r)/extra/`.
*   Crée `/etc/modules-load.d/kmon.conf` pour charger le module au démarrage.
*   Crée `/etc/modprobe.d/kmon.conf` pour définir les paramètres par défaut.
*   Crée `/etc/rsyslog.d/50-kmon.conf` pour rediriger les logs du module vers `/var/log/kmon.log`.

**Utilisation :**
```bash
# Installe et configure tout. Vous pouvez surcharger les paramètres par défaut.
sudo make persist MODULE_MATCH="passwd,shadow,group,hosts" MODULE_SYM="__x64_sys_openat2"

# Redémarre le service de logging pour prendre en compte la nouvelle configuration
sudo service rsyslog restart

# (Re)charger le module avec les nouveaux paramètres
sudo modprobe -r kmon 2>/dev/null || true
sudo modprobe kmon

# Vérifier que tout est en place
lsmod | grep kmon
cat /sys/module/kmon/parameters/match
tail -f /var/log/kmon.log
```

---

## 7) Désactiver / Désinstaller

```bash
# Décharger le module
sudo modprobe -r kmon 2>/dev/null || sudo rmmod kmon

# Pour retirer les fichiers de configuration et le module installé :
sudo rm -f /etc/modules-load.d/kmon.conf \
           /etc/modprobe.d/kmon.conf \
           /etc/rsyslog.d/50-kmon.conf \
           /lib/modules/$(uname -r)/extra/kmon.ko

# Mettre à jour les dépendances des modules et redémarrer le service de log
sudo depmod -a
sudo service rsyslog restart
```

---

## 8) Dépannage rapide

*   **`make` échoue avec "No such file or directory"**: Assurez-vous que les `linux-headers` correspondant à votre version de noyau (`uname -r`) sont bien installés.
*   **Avertissement « tainting kernel »**: C'est normal lors du chargement de modules non signés.
*   **`insmod ... File exists`**: Le module est déjà chargé. Utilisez `sudo rmmod kmon` pour le décharger.
*   **Rien dans `/var/log/kmon.log`**:
    1.  Vérifiez que `rsyslog` est installé et démarré (`sudo service rsyslog status`).
    2.  Vérifiez que le fichier de configuration `/etc/rsyslog.d/50-kmon.conf` existe et est correct.
    3.  Utilisez `dmesg | grep kmon` pour voir les logs bruts du noyau.
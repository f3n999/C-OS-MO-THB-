# Projet de Module Noyau Linux : Surveillance d'Appels Système

Ce projet est réalisé dans le cadre du cours de Système d'Exploitation de Hugo Chassaing et Julien Palard.

## Description

L'objectif est de développer un module noyau pour Linux capable de surveiller et de logger les appels système `openat` (et `openat2`) effectués sur des fichiers sensibles.

---

## 1) Pré-requis

### Alpine Linux (environnement de test)

```sh
# outils de build + logs + (headers du kernel)
apk update
apk add --no-cache git build-base kmod rsyslog linux-virt-dev \
  || apk add --no-cache linux-lts-dev \
  || apk add --no-cache linux-edge-dev
```

**IMPORTANT — headers Alpine et lien `build` :**
Le Makefile s’appuie sur `/lib/modules/$(uname -r)/build`. Sur Alpine, le répertoire d’en-têtes peut **supprimer** le `-0-` de `uname -r`. Crée (ou corrige) le lien :

```sh
# Exemple: uname -r => 6.12.52-0-virt ; headers => /usr/src/linux-headers-6.12.52-virt
HDR="/usr/src/linux-headers-$(uname -r)"; [ -d "$HDR" ] \
  || HDR="/usr/src/linux-headers-$(uname -r | sed 's/-[0-9]\+-/-/')"
ln -sf "$HDR" "/lib/modules/$(uname -r)/build"
ls -l "/lib/modules/$(uname -r)/build"
```

> Si les headers EXACTS n’existent pas pour votre noyau courant : alignez le noyau **et** les headers sur la même version (ex. `6.12.52-r0`), puis **reboot**:
>
> ```sh
> apk policy linux-virt linux-virt-dev
> apk add --no-cache linux-virt=6.x.y-rz linux-virt-dev=6.x.y-rz
> reboot
> ```

**Plugins GCC (Alpine)**
Si vous voyez des erreurs `stackleak_plugin.so` / `latent_entropy_plugin.so` (GCC14 vs GCC15), compilez avec :

```sh
make NO_PLUGINS=1
```

### Debian/Ubuntu (au cas où)

```bash
sudo apt-get update
sudo apt-get install -y git build-essential linux-headers-$(uname -r) rsyslog
```

> **Pourquoi ?** `linux-headers-$(uname -r)` fournit l’arborescence `/lib/modules/<version>/build` utilisée pour compiler le module **contre le noyau en cours d’exécution**.

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
# Alpine (si plugins GCC foireux) :
make NO_PLUGINS=1
```

Vous devriez voir un fichier `kmon.ko` à la racine du projet.

**Avertissements fréquents (OK) :**

*   `warning: the compiler differs from the one used to build the kernel` (ex. GCC 15 vs GCC 14)
*   `module verification failed: signature...` (module non signé)

---

## 4) Charger le module à la main (test rapide)

Le module accepte deux paramètres :

*   `match` : noms de fichiers/mots-clés surveillés, séparés par des virgules (ex: `"passwd,shadow"`).
*   `sym` : symbole du syscall à accrocher (ex: `__x64_sys_openat` ou `__x64_sys_openat2`).

**Vérifier les symboles disponibles :**
```bash
grep -E "__x64_sys_openat2|__x64_sys_openat" /proc/kallsyms | head
```

**Charger le module :**
```bash
# Essayer d'abord openat2 (musl/Alpine l’utilise souvent), sinon fallback openat
sudo insmod ./kmon.ko match="passwd,shadow,group,hosts" sym="__x64_sys_openat2" 2>/dev/null || \
sudo insmod ./kmon.ko match="passwd,shadow,group,hosts" sym="__x64_sys_openat"
```

> Si vous obtenez `insmod: ERROR: could not insert module ...: File exists`, le module est déjà chargé.

**Vérifier l'état du module :**
```bash
lsmod | grep kmon
cat /sys/module/kmon/parameters/match
cat /sys/module/kmon/parameters/sym
dmesg | tail -n 20 | grep -i kmon
```

---

## 5) Voir les logs

Le module écrit dans le ring buffer du noyau.

**Déclencher un événement de test :**
```bash
# Outil de test (ouvre /etc/passwd et tente /etc/shadow)
./tools/kmon_trigger

# Ou manuellement
cat /etc/passwd > /dev/null
sudo sh -c 'cat /etc/shadow > /dev/null || true'   # tracé même si l’accès échoue
```

**Consulter les logs :**
```bash
# flux direct
sudo dmesg -w | grep --line-buffered "kmon:"

# aperçu rapide
dmesg | grep -F "kmon:" | tail -n 50
```

---

## 6) (Optionnel) Rendre l’usage « confortable » (Installation & Persistance)

Le `Makefile` inclut des cibles pour automatiser l’installation et la configuration.

**Ce que fait `make persist` :**

*   Installe `kmon.ko` dans `/lib/modules/$(uname -r)/extra/`
*   Crée `/etc/modules-load.d/kmon.conf` (chargement au boot)
*   Crée `/etc/modprobe.d/kmon.conf` (paramètres par défaut)
*   Crée `/etc/rsyslog.d/50-kmon.conf` (redirige vers `/var/log/kmon.log`)

**Utilisation :**
```bash
# Installe et configure tout. Vous pouvez surcharger les paramètres par défaut.
sudo make persist MODULE_MATCH="passwd,shadow,group,hosts" MODULE_SYM="__x64_sys_openat2"

# Redémarrer le service de logs (selon init)
sudo systemctl restart rsyslog 2>/dev/null || sudo service rsyslog restart 2>/dev/null || sudo rc-service rsyslog restart 2>/dev/null

# (Re)charger
sudo modprobe -r kmon 2>/dev/null || true
sudo modprobe kmon

# Vérifier
lsmod | grep kmon
cat /sys/module/kmon/parameters/match
tail -f /var/log/kmon.log
```

---

## 7) Désactiver / Désinstaller

```bash
# Décharger le module
sudo modprobe -r kmon 2>/dev/null || sudo rmmod kmon

# Retirer la persistance et les fichiers installés
sudo rm -f /etc/modules-load.d/kmon.conf \
           /etc/modprobe.d/kmon.conf \
           /etc/rsyslog.d/50-kmon.conf \
           /lib/modules/$(uname -r)/extra/kmon.ko

sudo depmod -a
sudo systemctl restart rsyslog 2>/dev/null || sudo service rsyslog restart 2>/dev/null || sudo rc-service rsyslog restart 2>/dev/null
```

---

## 8) Dépannage rapide

*   **`make: .../build: No such file or directory`**
  Headers absents ou version non concordante. Sur Alpine, créez le lien `build` (voir §1) **et** alignez le noyau/headers si nécessaire.

*   **Erreurs plugins GCC (Alpine)**
  `stackleak_plugin.so` / `latent_entropy_plugin.so` → `make NO_PLUGINS=1`.

*   **Pas de logs**
  Forcez `openat2` lors du chargement :
  `sudo insmod ./kmon.ko match="..." sym="__x64_sys_openat2"`
  (Vérifiez les symboles avec `grep -E '__x64_sys_openat(2)?' /proc/kallsyms`.)

*   **Messages BTF “Skipping vmlinux”**
  Purement informatif.

*   **Avertissements “taints kernel” / “signature missing”**
  Normaux pour un module non signé (hors Secure Boot strict).
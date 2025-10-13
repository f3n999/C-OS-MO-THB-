#include <linux/init.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#include "kmon.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jules AI Assistant");
MODULE_DESCRIPTION("A simple LKM to monitor file access using kprobes.");
MODULE_VERSION("1.0");

static char *match = "passwd,shadow";
module_param(match, charp, 0444);
MODULE_PARM_DESC(match, "Liste CSV de mots-clés à matcher dans le chemin");

static char *sym = "__x64_sys_openat";
module_param(sym, charp, 0444);
MODULE_PARM_DESC(sym, "Symbole de syscall à kprober (__x64_sys_openat ou __x64_sys_openat2)");

static struct kprobe kp;
static char tokens[256];

/*
 * strsep - C'est une fonction de bibliothèque standard, mais pas toujours
 * disponible dans le noyau, donc nous fournissons une implémentation simple.
 */
static char *k_strsep(char **s, const char *ct)
{
    char *sbegin = *s;
    char *end;

    if (sbegin == NULL) {
        return NULL;
    }

    end = strpbrk(sbegin, ct);
    if (end) {
        *end++ = '\0';
    }
    *s = end;
    return sbegin;
}

/* Test si path contient au moins un token CSV de 'match' */
static bool path_matches(const char *path)
{
    char *p_tokens = tokens;
    char *token;

    // strsep modifie la chaîne, donc on utilise une copie
    strlcpy(tokens, match, sizeof(tokens));

    while ((token = k_strsep(&p_tokens, ",")) != NULL) {
        if (*token == '\0') {
            continue;
        }
        if (strstr(path, token)) {
            return true;
        }
    }
    return false;
}

/* Récupère l’argument “const char __user *filename” selon le syscall choisi */
static const char __user *get_user_filename(const struct pt_regs *regs)
{
#if defined(__x86_64__)
    /* ABI x86_64:
     * 1st argument: %rdi
     * 2nd argument: %rsi
     * 3rd argument: %rdx
     * ...
     * openat(int dfd, const char __user *filename, int flags, umode_t mode)
     * Le nom du fichier est le deuxième argument (regs->si).
     */
    return (const char __user *)regs->si;
#elif defined(__aarch64__)
    /* ABI aarch64:
     * Les premiers 8 arguments sont dans les registres x0 à x7.
     * Le nom du fichier est le deuxième argument (regs->regs[1]).
     */
    return (const char __user *)regs->regs[1];
#else
#warning "Unsupported architecture for syscall argument retrieval."
    return NULL;
#endif
}

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    char path[PATH_MAX];
    const char __user *filename_user_ptr = get_user_filename(regs);

    if (!filename_user_ptr) {
        return 0;
    }

    // Copie sécurisée du nom de fichier depuis l'espace utilisateur
    if (strncpy_from_user(path, filename_user_ptr, sizeof(path)) > 0) {
        if (path_matches(path)) {
            pr_info("%s: Access to '%s' by process '%s' (PID: %d)\n",
                    DRV_NAME, path, current->comm, current->pid);
        }
    }

    return 0;
}

static int register_probe(const char *symbol)
{
    int ret;
    kp.symbol_name = symbol;
    kp.pre_handler = pre_handler;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("%s: register_kprobe failed for symbol %s, returned %d\n", DRV_NAME, symbol, ret);
        return ret;
    }
    pr_info("%s: Planted kprobe at %p on symbol %s\n", DRV_NAME, kp.addr, symbol);
    return 0;
}

static int __init kmon_init(void)
{
    int ret;

    pr_info("%s: Initializing module. Monitoring: '%s'\n", DRV_NAME, match);

    // Essayer le symbole spécifié
    ret = register_probe(sym);
    if (ret < 0) {
        // Fallback vers __x86_64_sys_openat si le premier échoue
        if (strcmp(sym, "do_sys_openat") == 0 || strcmp(sym, "__x86_64_sys_openat2") == 0) {
            pr_info("%s: Retrying with __x86_64_sys_openat\n", DRV_NAME);
            ret = register_probe("__x86_64_sys_openat");
        }
        // Fallback vers do_sys_openat2 si le premier échoue
        else if(strcmp(sym, "__x86_64_sys_openat") == 0) {
            pr_info("%s: Retrying with do_sys_openat2\n", DRV_NAME);
            ret = register_probe("do_sys_openat2");
        }
    }

    if (ret < 0) {
        pr_err("%s: Failed to register kprobe on any symbol.\n", DRV_NAME);
        return ret;
    }

    return 0;
}

static void __exit kmon_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("%s: Module unloaded.\n", DRV_NAME);
}

module_init(kmon_init);
module_exit(kmon_exit);
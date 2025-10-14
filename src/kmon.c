// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/timekeeping.h>  // ktime_get_real_ts64
#include <linux/time64.h>       // time64_to_tm
#include <linux/ptrace.h>       // regs_return_value()
#include <linux/types.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#include <uapi/linux/openat2.h> // struct open_how
#else
/* Fallback minimal si openat2.h n'existe pas (vieux noyaux) */
struct open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};
#endif

#define KMON_TAG "kmon"

static char match[256] = "passwd,shadow,group,hosts";
module_param_string(match, match, sizeof(match), 0644);
MODULE_PARM_DESC(match, "Mots-clés CSV (ex: \"passwd,shadow\")");

static char sym[64] = "";
module_param_string(sym, sym, sizeof(sym), 0444);
MODULE_PARM_DESC(sym, "Symbole cible unique (\"__x64_sys_openat\" ou \"__x64_sys_openat2\"). Par défaut, les deux.");

static bool log_all = false;
module_param(log_all, bool, 0644);
MODULE_PARM_DESC(log_all, "Logguer même sans match (défaut: false)");

/* --- tokenisation des mots-clés --- */
static char *match_buf;
static char *words[32];
static int nwords;

static int parse_words(const char *csv)
{
	int i = 0;
	char *p, *s;

	if (!csv || !*csv)
		return 0;

	match_buf = kstrdup(csv, GFP_KERNEL);
	if (!match_buf)
		return -ENOMEM;

	p = match_buf;
	while ((s = strsep(&p, ",")) != NULL) {
		if (*s == '\0')
			continue;
		words[i++] = s;
		if (i >= ARRAY_SIZE(words))
			break;
	}
	nwords = i;
	return 0;
}

static bool match_path(const char *path)
{
	int i;
	if (!path || !*path || nwords == 0)
		return false;
	for (i = 0; i < nwords; i++) {
		if (strstr(path, words[i]))
			return true;
	}
	return false;
}

/* --- extraction d'arguments suivant l'arch --- */
#if defined(__x86_64__)
/* openat(dirfd=di, filename=si, flags=dx, mode=r10) */
# define AT_FILENAME(regs) ((const char __user *)(regs->si))
# define AT_FLAGS(regs)    ((int)(regs->dx))
# define AT_MODE(regs)     ((umode_t)(regs->r10))
/* openat2(dirfd=di, filename=si, how*=dx, size=r10) */
# define AT2_FILENAME(regs) ((const char __user *)(regs->si))
# define AT2_HOWPTR(regs)   ((const void __user *)(regs->dx))
#elif defined(__aarch64__)
/* openat: x0=dirfd, x1=filename, x2=flags, x3=mode */
# define AT_FILENAME(regs)  ((const char __user *)(regs->regs[1]))
# define AT_FLAGS(regs)     ((int)(regs->regs[2]))
# define AT_MODE(regs)      ((umode_t)(regs->regs[3]))
/* openat2: x0=dirfd, x1=filename, x2=how*, x3=size */
# define AT2_FILENAME(regs) ((const char __user *)(regs->regs[1]))
# define AT2_HOWPTR(regs)   ((const void __user *)(regs->regs[2]))
#else
# warning "Arch non testée: définitions par défaut (peuvent être incorrectes)"
# define AT_FILENAME(regs)  (NULL)
# define AT_FLAGS(regs)     (0)
# define AT_MODE(regs)      (0)
# define AT2_FILENAME(regs) (NULL)
# define AT2_HOWPTR(regs)   (NULL)
#endif

/* --- données par appel (entre entry et ret) --- */
struct kmon_data {
	char *path;                 /* copie kernel du filename */
	unsigned int flags;
	umode_t mode;
	kuid_t uid;
	kgid_t gid;
	pid_t pid, tgid;
	char comm[TASK_COMM_LEN];
	bool matched;
	struct timespec64 ts_entry; /* horodatage à l'entrée */
};

static struct kretprobe rp_at;   /* __x64_sys_openat      */
static struct kretprobe rp_at2;  /* __x64_sys_openat2     */
static bool at_registered, at2_registered;

/* -------- entry handlers -------- */

static int entry_openat(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kmon_data *d = (struct kmon_data *)ri->data;
	const char __user *upath = AT_FILENAME(regs);
	long n;

	d->path = NULL;

	ktime_get_real_ts64(&d->ts_entry);
	d->flags = AT_FLAGS(regs);
	d->mode  = AT_MODE(regs);

	d->uid  = current_uid();
	d->gid  = current_gid();
	d->pid  = task_pid_nr(current);
	d->tgid = task_tgid_nr(current);
	strscpy(d->comm, current->comm, sizeof(d->comm));

	if (!upath)
		return 0;

	d->path = kmalloc(PATH_MAX, GFP_ATOMIC);
	if (!d->path)
		return 0;

	n = strncpy_from_user(d->path, upath, PATH_MAX - 1);
	if (n < 0) {
		kfree(d->path);
		d->path = NULL;
		return 0;
	}
	d->path[PATH_MAX - 1] = '\0';

	d->matched = match_path(d->path);
	return 0;
}

static int entry_openat2(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kmon_data *d = (struct kmon_data *)ri->data;
	const char __user *upath = AT2_FILENAME(regs);
	const struct open_how __user *uhow = (const struct open_how __user *)AT2_HOWPTR(regs);
	struct open_how how;
	long n;

	d->path = NULL;

	ktime_get_real_real_ts64(&d->ts_entry);

	/* défauts si open_how illisible */
	d->flags = 0;
	d->mode  = 0;

	if (uhow) {
		if (copy_from_user(&how, uhow, sizeof(how)) == 0) {
			d->flags = (unsigned int)how.flags;
			d->mode  = (umode_t)how.mode;
		}
	}

	d->uid  = current_uid();
	d->gid  = current_gid();
	d->pid  = task_pid_nr(current);
	d->tgid = task_tgid_nr(current);
	strscpy(d->comm, current->comm, sizeof(d->comm));

	if (!upath)
		return 0;

	d->path = kmalloc(PATH_MAX, GFP_ATOMIC);
	if (!d->path)
		return 0;

	n = strncpy_from_user(d->path, upath, PATH_MAX - 1);
	if (n < 0) {
		kfree(d->path);
		d->path = NULL;
		return 0;
	}
	d->path[PATH_MAX - 1] = '\0';

	d->matched = match_path(d->path);
	return 0;
}

/* -------- return handler (commun) -------- */

static int handler_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kmon_data *d = (struct kmon_data *)ri->data;
	long ret = regs_return_value(regs);
	struct tm tm;
	long year, mon, mday, hour, min, sec, msec;

	time64_to_tm(d->ts_entry.tv_sec, 0, &tm);
	year = tm.tm_year + 1900;
	mon  = tm.tm_mon + 1;
	mday = tm.tm_mday;
	hour = tm.tm_hour;
	min  = tm.tm_min;
	sec  = tm.tm_sec;
	msec = d->ts_entry.tv_nsec / 1000000;

	if ((d->matched || log_all) && d->path) {
		pr_info(KMON_TAG ": %04ld-%02ld-%02ldT%02ld:%02ld:%02ld.%03ldZ "
		                "pid=%d tgid=%d uid=%u gid=%u comm=%s "
		                "ret=%ld%s flags=0x%x mode=%04o path=%s\n",
		        year, mon, mday, hour, min, sec, msec,
		        d->pid, d->tgid,
		        __kuid_val(d->uid), __kgid_val(d->gid),
		        d->comm,
		        ret, (ret >= 0 ? " (ok)" : " (errno)"),
		        d->flags, d->mode,
		        d->path);
	}

	kfree(d->path);
	d->path = NULL;
	return 0;
}

/* -------- registration -------- */

static int register_on(const char *symbol, bool is_openat2)
{
	struct kretprobe *rp = is_openat2 ? &rp_at2 : &rp_at;

	memset(rp, 0, sizeof(*rp));
	rp->kp.symbol_name = symbol;
	rp->entry_handler  = is_openat2 ? entry_openat2 : entry_openat;
	rp->handler        = handler_ret;
	rp->data_size      = sizeof(struct kmon_data);
	rp->maxactive      = 128;

	return register_kretprobe(rp);
}

static int __init kmon_init(void)
{
	int ret, ok = 0;

	ret = parse_words(match);
	if (ret) {
		pr_err(KMON_TAG ": parse failed match=\"%s\" (%d)\n", match, ret);
		return ret;
	}

	if (sym[0]) {
		/* forcer un seul symbole */
		if (strstr(sym, "openat2")) {
			ret = register_on("__x64_sys_openat2", true);
			if (ret) {
				pr_err(KMON_TAG ": cannot kretprobe %s (%d)\n", "__x64_sys_openat2", ret);
				kfree(match_buf);
				return ret;
			}
			at2_registered = true; ok++;
			pr_info(KMON_TAG ": loaded (kretprobe on __x64_sys_openat2, match=\"%s\", log_all=%d)\n", match, log_all);
		} else {
			ret = register_on("__x64_sys_openat", false);
			if (ret) {
				pr_err(KMON_TAG ": cannot kretprobe %s (%d)\n", "__x64_sys_openat", ret);
				kfree(match_buf);
				return ret;
			}
			at_registered = true; ok++;
			pr_info(KMON_TAG ": loaded (kretprobe on __x64_sys_openat, match=\"%s\", log_all=%d)\n", match, log_all);
		}
		return 0;
	}

	/* Par défaut: on tente les deux */
	ret = register_on("__x64_sys_openat", false);
	if (!ret) { at_registered = true; ok++; }
	ret = register_on("__x64_sys_openat2", true);
	if (!ret) { at2_registered = true; ok++; }

	if (!ok) {
		pr_err(KMON_TAG ": cannot kretprobe openat and openat2\n");
		kfree(match_buf);
		return -ENOENT;
	}

	pr_info(KMON_TAG ": loaded (%s%s%s, match=\"%s\", log_all=%d)\n",
	        at_registered ? "kretprobe on __x64_sys_openat" : "",
	        (at_registered && at2_registered) ? " + " : "",
	        at2_registered ? "kretprobe on __x64_sys_openat2" : "",
	        match, log_all);
	return 0;
}

static void __exit kmon_exit(void)
{
	if (at_registered)
		unregister_kretprobe(&rp_at);
	if (at2_registered)
		unregister_kretprobe(&rp_at2);
	kfree(match_buf);
	pr_info(KMON_TAG ": unloaded\n");
}

MODULE_AUTHOR("toi + moi");
MODULE_DESCRIPTION("kretprobe openat/openat2 — audit mots-clés, horodatage, uid/gid, flags/mode, ret");
MODULE_LICENSE("GPL");

module_init(kmon_init);
module_exit(kmon_exit);
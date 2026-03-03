#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>    // Macros for module initialization
#include <linux/kernel.h>  // Kernel logging macros
#include <linux/module.h>  // Core header for loading modules

#define info(fmt, ...) \
    printk(KERN_INFO "bpf_string_kfunc: " fmt, ##__VA_ARGS__)

#define err(fmt, ...) \
    printk(KERN_ERR "bpf_string_kfunc: " fmt, ##__VA_ARGS__)

/* Declare the kfunc prototype */
__bpf_kfunc int bpf_strcmp(const char *s1, const char *s2);
__bpf_kfunc int bpf_strstr(const char *s1, const char *s2);

/* Begin kfunc definitions */
__bpf_kfunc_start_defs();

/* Define the bpf_strstr kfunc */
__bpf_kfunc int bpf_strcmp(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        if (*s1 != *s2) {
            return (unsigned char)*s1 - (unsigned char)*s2;
        }
        s1++;
        s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

__bpf_kfunc int bpf_strstr(const char *s1, const char *s2) {
    // Return index of first character of first occurrence of s2 within s1, or -1 if not found
    int i, j;
    for (i = 0; i < XATTR_SIZE_MAX; i++) {
        for (j = 0; j < XATTR_SIZE_MAX; j++) {
            if (s2[j] == '\0') return i;
            if (s1[i + j] != s2[j]) break;
        }
    }
    return -1;  // No match found
}

/* End kfunc definitions */
__bpf_kfunc_end_defs();

/* Define the BTF kfuncs ID set */
BTF_KFUNCS_START(bpf_string_kfunc_ids_set)
BTF_ID_FLAGS(func, bpf_strcmp)
BTF_ID_FLAGS(func, bpf_strstr)
BTF_KFUNCS_END(bpf_string_kfunc_ids_set)

/* Register the kfunc ID set */
static const struct btf_kfunc_id_set bpf_string_kfunc_set = {
    .owner = THIS_MODULE,
    .set = &bpf_string_kfunc_ids_set,
};

/* Function executed when the module is loaded */
static int __init strings_init(void) {
    int ret;

    info("String utilities module loaded\n");
    /* Register the BTF kfunc ID set for BPF_PROG_TYPE_UNSPEC */
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &bpf_string_kfunc_set);
    if (ret) {
        err("bpf_string_kfunc: Failed to register BTF kfunc ID set\n");
        return ret;
    }
    info("bpf_string_kfunc: Module loaded successfully\n");
    return 0;  // Return 0 if successful
}

/* Function executed when the module is removed */
static void __exit strings_exit(void) {
    info("String utilities module unloaded\n");
}

/* Macros to define the module’s init and exit points */
module_init(strings_init);
module_exit(strings_exit);

MODULE_LICENSE("GPL");                   // License type (GPL)
MODULE_AUTHOR("Yuzuki Ishiyama");        // Module author
MODULE_DESCRIPTION("String utilities");  // Module description
MODULE_VERSION("1.0");                   // Module version

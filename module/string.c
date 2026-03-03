#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>    // Macros for module initialization
#include <linux/kernel.h>  // Kernel logging macros
#include <linux/module.h>  // Core header for loading modules

/* Declare the kfunc prototype */
__bpf_kfunc int bpf_strcmp(const char *s1, const char *s2);
__bpf_kfunc int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz);
__bpf_kfunc int bpf_strcasestr(const char *s1, u32 len1, const char *s2, u32 len2);

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

__bpf_kfunc int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz) {
    // Edge case: if substr is empty, return 0 (assuming empty string is found at the start)
    if (substr__sz == 0) {
        return 0;
    }
    // Edge case: if the substring is longer than the main string, it's impossible to find
    if (substr__sz > str__sz) {
        return -1;  // Return -1 to indicate not found
    }
    // Iterate through the main string, considering the size limit
    for (size_t i = 0; i <= str__sz - substr__sz; i++) {
        size_t j = 0;
        // Compare the substring with the current position in the string
        while (j < substr__sz && str[i + j] == substr[j]) {
            j++;
        }
        // If the entire substring was found
        if (j == substr__sz) {
            return i;  // Return the index of the first match
        }
    }
    // Return -1 if the substring is not found
    return -1;
}

__bpf_kfunc int bpf_strcasestr(const char *s1, u32 len1, const char *s2, u32 len2) {
    // Edge case: if s2 is empty, return 0 (assuming empty string is found at the start)
    if (len2 == 0) {
        return 0;
    }
    // Edge case: if s2 is longer than s1, it's impossible to find
    if (len2 > len1) {
        return -1;  // Return -1 to indicate not found
    }
    // Iterate through the main string, considering the size limit
    for (size_t i = 0; i <= len1 - len2; i++) {
        size_t j = 0;
        // Compare the substring with the current position in the string (case-insensitive)
        while (j < len2) {
            char c1 = s1[i + j];
            char c2 = s2[j];
            // // Convert both characters to lowercase for comparison
            c1 = tolower(c1);
            c2 = tolower(c2);
            if (c1 != c2) {
                break;
            }
            j++;
        }
        // If the entire substring was found
        if (j == len2) {
            return i;  // Return the index of the first match
        }
    }
    // Return -1 if the substring is not found
    return -1;
}

/* End kfunc definitions */
__bpf_kfunc_end_defs();

/* Define the BTF kfuncs ID set */
BTF_KFUNCS_START(bpf_string_kfunc_ids_set)
BTF_ID_FLAGS(func, bpf_strcmp)
BTF_ID_FLAGS(func, bpf_strstr)
BTF_ID_FLAGS(func, bpf_strcasestr)
BTF_KFUNCS_END(bpf_string_kfunc_ids_set)

/* Register the kfunc ID set */
static const struct btf_kfunc_id_set bpf_string_kfunc_set = {
    .owner = THIS_MODULE,
    .set = &bpf_string_kfunc_ids_set,
};

/* Function executed when the module is loaded */
static int __init strings_init(void) {
    int ret;

    pr_info("String utilities module loaded\n");
    /* Register the BTF kfunc ID set for BPF_PROG_TYPE_UNSPEC */
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &bpf_string_kfunc_set);
    if (ret) {
        pr_err("bpf_string_kfunc: Failed to register BTF kfunc ID set\n");
        return ret;
    }
    pr_info("bpf_string_kfunc: Module loaded successfully\n");
    return 0;  // Return 0 if successful
}

/* Function executed when the module is removed */
static void __exit strings_exit(void) {
    pr_info("String utilities module unloaded\n");
}

/* Macros to define the module’s init and exit points */
module_init(strings_init);
module_exit(strings_exit);

MODULE_LICENSE("GPL");                   // License type (GPL)
MODULE_AUTHOR("Yuzuki Ishiyama");        // Module author
MODULE_DESCRIPTION("String utilities");  // Module description
MODULE_VERSION("1.0");                   // Module version

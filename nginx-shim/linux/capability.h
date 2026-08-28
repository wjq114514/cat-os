
#ifndef _SHIM_LINUX_CAPABILITY_H
#define _SHIM_LINUX_CAPABILITY_H
typedef struct __user_cap_header_struct { uint32_t version; int pid; } *cap_user_header_t;
typedef struct __user_cap_data_struct { uint32_t effective; uint32_t permitted; uint32_t inheritable; } *cap_user_data_t;
#define _LINUX_CAPABILITY_VERSION_3 0x20080522
#define _LINUX_CAPABILITY_VERSION_1 0x19980330
#define CAP_NET_RAW 13
#define CAP_TO_MASK(x) (1 << (x))
static inline int capget(cap_user_header_t h, cap_user_data_t d){(void)h;(void)d;return -1;}
static inline int capset(cap_user_header_t h, cap_user_data_t d){(void)h;(void)d;return -1;}
#endif

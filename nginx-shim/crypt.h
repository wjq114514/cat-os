
#ifndef _SHIM_CRYPT_H
#define _SHIM_CRYPT_H
char *crypt(const char *, const char *);
struct crypt_data { int initialized; char internal[128]; };
char *crypt_r(const char *, const char *, struct crypt_data *);
#endif

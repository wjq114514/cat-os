#ifndef CATOS_USER_H
#define CATOS_USER_H
#include <stdint.h>
typedef struct {uint32_t eip,esp,cs,ss,esp0;} user_context_t;
void usermode_init(void);
void enter_usermode(void);
#endif

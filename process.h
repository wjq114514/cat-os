#ifndef CATOS_PROCESS_H
#define CATOS_PROCESS_H
#include <stdint.h>
typedef struct {uint32_t page_dir,heap_base,stack_top;} address_space_t;
typedef struct {uint32_t pid,state;address_space_t *as;} process_t;
void process_init(void);
#endif

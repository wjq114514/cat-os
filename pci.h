#ifndef CATOS_PCI_H
#define CATOS_PCI_H
#include <stdint.h>
typedef struct {uint8_t bus,dev,fn;uint16_t vendor,device;uint8_t class_code,subclass,header_type;} pci_device_t;
typedef void (*pci_class_callback_t)(const pci_device_t *,void *);
uint32_t pci_read_config(uint8_t bus,uint8_t dev,uint8_t fn,uint8_t off,uint8_t size);
void pci_write_config(uint8_t bus,uint8_t dev,uint8_t fn,uint8_t off,uint8_t size,uint32_t value);
void pci_find_class(uint8_t class_code,uint8_t subclass,pci_class_callback_t cb,void *arg);
void pci_init(void);
#endif

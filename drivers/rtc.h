#ifndef CATOS_RTC_H
#define CATOS_RTC_H
#include <stdint.h>
typedef struct {unsigned second,minute,hour,day,month,year;} rtc_time_t;
void rtc_init(void); rtc_time_t rtc_get_time(void);
uint32_t rtc_get_epoch(void);
#endif

#ifndef CATOS_RTC_H
#define CATOS_RTC_H
typedef struct {unsigned second,minute,hour,day,month,year;} rtc_time_t;
void rtc_init(void); rtc_time_t rtc_get_time(void);
#endif


#ifndef _SHIM_STDIO_H
#define _SHIM_STDIO_H
#include <sys/types.h>
typedef struct FILE FILE;
extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;
FILE *fopen(const char *, const char *);
int fclose(FILE *);
size_t fread(void *, size_t, size_t, FILE *);
size_t fwrite(const void *, size_t, size_t, FILE *);
int fprintf(FILE *, const char *, ...);
int printf(const char *, ...);
int sprintf(char *, const char *, ...);
int snprintf(char *, size_t, const char *, ...);
int sscanf(const char *, const char *, ...);
int vfprintf(FILE *, const char *, __builtin_va_list);
int vsprintf(char *, const char *, __builtin_va_list);
int vsnprintf(char *, size_t, const char *, __builtin_va_list);
int fgetc(FILE *);
char *fgets(char *, int, FILE *);
int fputc(int, FILE *);
int fputs(const char *, FILE *);
int puts(const char *);
int putchar(int);
int fseek(FILE *, long, int);
long ftell(FILE *);
void rewind(FILE *);
int feof(FILE *);
int ferror(FILE *);
void perror(const char *);
int fflush(FILE *);
int ftruncate(int, off_t);
#endif

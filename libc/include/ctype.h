/*
 * ctype.h —— Cat-OS 最小用户态 C 库：字符分类/大小写转换声明
 * ─────────────────────────────────────────────────────────────────────────────
 * freestanding 头文件自洽：不 include 任何系统头。
 * "C" locale 固定语义（无 locale 机制）；实现在 ctype.c，纯查界判断无表。
 *
 * 参数约定：标准要求 c 为 EOF 或 unsigned char 可表示值 [0,255]。
 * 本实现防御性兼容：越界值一律按"非字符"处理——分类函数返回 0，
 * tolower/toupper 原样返回入参（不产生越界访问）。
 */

#ifndef CATOS_LIBC_CTYPE_H
#define CATOS_LIBC_CTYPE_H

int isalnum(int c); /* [0-9A-Za-z] */
int isalpha(int c); /* [A-Za-z] */
int isblank(int c); /* ' ' \t（单词分隔空白） */
int iscntrl(int c); /* [0x00,0x1F] ∪ DEL(0x7F) */
int isdigit(int c); /* [0-9] */
int isgraph(int c); /* isprint 且非空格 */
int islower(int c); /* [a-z] */
int isprint(int c); /* [0x20,0x7E] */
int ispunct(int c); /* isgraph 且非 alnum */
int isspace(int c); /* ' ' \f \n \r \t \v */
int isupper(int c); /* [A-Z] */
int isxdigit(int c);/* [0-9A-Fa-f] */

int tolower(int c); /* 大写→小写；其余原样返回 */
int toupper(int c); /* 小写→大写；其余原样返回 */

#endif /* CATOS_LIBC_CTYPE_H */

/*
 * ctype.c —— Cat-OS 最小用户态 C 库：字符分类/大小写转换实现
 * ─────────────────────────────────────────────────────────────────────────────
 * 纯实现，无 syscall、无查找表（区间判断直接内联为比较序列，-O2 下即分支消除）。
 * 防御性约定见 ctype.h 头注释：EOF(-1) 与 >255 的入参不越界、分类恒 0。
 */

#include "ctype.h"

/* EOF/越界哨兵：仅 [0,255] 视为合法字符码 */
static int catos_ctype_in_range(int c)
{
    return (c >= 0 && c <= 255);
}

int isalnum(int c)
{
    return isdigit(c) || isalpha(c);
}

int isalpha(int c)
{
    if (!catos_ctype_in_range(c))
        return 0;
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) ? 1 : 0;
}

int isblank(int c)
{
    return (c == ' ' || c == '\t') ? 1 : 0;
}

int iscntrl(int c)
{
    if (!catos_ctype_in_range(c))
        return 0;
    return ((c >= 0 && c <= 0x1F) || c == 0x7F) ? 1 : 0;
}

int isdigit(int c)
{
    return (c >= '0' && c <= '9') ? 1 : 0;
}

int isgraph(int c)
{
    return (c > 0x20 && c < 0x7F) ? 1 : 0;
}

int islower(int c)
{
    return (c >= 'a' && c <= 'z') ? 1 : 0;
}

int isprint(int c)
{
    return (c >= 0x20 && c < 0x7F) ? 1 : 0;
}

int ispunct(int c)
{
    return (isgraph(c) && !isalnum(c)) ? 1 : 0;
}

int isspace(int c)
{
    return (c == ' ' || (c >= '\t' && c <= '\r')) ? 1 : 0;
}

int isupper(int c)
{
    return (c >= 'A' && c <= 'Z') ? 1 : 0;
}

int isxdigit(int c)
{
    return (isdigit(c) || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))
               ? 1
               : 0;
}

int tolower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c;
}

int toupper(int c)
{
    return (c >= 'a' && c <= 'z') ? c - 'a' + 'A' : c;
}

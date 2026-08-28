/*
 * errno.c —— Cat-OS 最小用户态 C 库：errno 存储（单一定义点）
 * ─────────────────────────────────────────────────────────────────────────────
 * 仅 errno.h 声明过的全局实体；ring3 单线程无并发写问题。
 * 置零初始化：进程启动即处于"无错误"状态。
 */

#include "errno.h"

int errno;

int *__errno_location(void)
{
    return &errno;
}

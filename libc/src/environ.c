/*
 * environ.c —— Cat-OS 最小用户态 C 库：环境变量实现
 * ─────────────────────────────────────────────────────────────────────────────
 * 纯用户态实现：存储经现有 malloc/free 动态增长，无 exec 传参通道，
 * 初始为空表。数据布局：
 *   environ        —— NULL 结尾的 "NAME=value" 指针数组（对外可见）
 *   catos_env_owned—— 与槽位一一对应的"本库分配"标记数组
 *                     （setenv 创建的串在替换/移除时回收；putenv 纳入的
 *                      串所有权归调用方契约，永不 free）
 *
 * 每次增删都重建指针数组（拷贝指针而非字符串），旧数组即释放；
 * 失败路径保持原环境不动。ring3 单线程，无锁。
 */

#include "stdlib.h"
#include "string.h"

char **environ;

static unsigned char *catos_env_owned; /* 槽位所有权标记（与 environ 对齐） */
static unsigned int catos_env_cap;     /* 已分配槽数（不含终结 NULL）     */

/* 在 name 项查找：命中返回槽位下标，未命中返回 -1。
 * 匹配规则：前缀等于 name 且其后恰为 '='。 */
static int catos_env_find(const char *name, unsigned int nl)
{
    if (environ == (char **)0)
        return -1;
    for (unsigned int i = 0u; environ[i] != (char *)0; i++) {
        const char *e = environ[i];

        if (strncmp(e, name, nl) == 0 && e[nl] == '=')
            return (int)i;
    }
    return -1;
}

/* 校验 name 合法性：非空且不含 '='。返回长度或 0 表示非法 */
static unsigned int catos_env_name_len(const char *name)
{
    if (name == (const char *)0 || *name == '\0')
        return 0u;
    for (unsigned int i = 0u; name[i] != '\0'; i++)
        if (name[i] == '=')
            return 0u;
    return strlen(name);
}

int setenv(const char *name, const char *value, int overwrite)
{
    unsigned int nl = catos_env_name_len(name);
    unsigned int vl;
    int idx;

    if (nl == 0u)
        return -1;
    if (value == (const char *)0)
        value = "";
    vl = strlen(value);

    idx = catos_env_find(name, nl);
    if (idx >= 0 && overwrite == 0)
        return 0; /* 已存在且禁止覆盖：按标准为成功无操作 */

    /* 构造新串（始终新分配：旧串回收与否由槽位标记决定） */
    {
        char *s = malloc((size_t)nl + 1u + vl + 1u);

        if (s == (char *)0)
            return -1; /* 原环境保持不变 */
        memcpy(s, name, nl);
        s[nl] = '=';
        memcpy(s + nl + 1u, value, vl + 1u);

        if (idx >= 0) { /* 替换 */
            if (catos_env_owned != (unsigned char *)0 &&
                catos_env_owned[idx] != 0u)
                free(environ[idx]);
            environ[idx] = s;
            /* owned[idx] 保持 1：新串仍是本库所有 */
        } else { /* 追加：重建扩容一槽 */
            unsigned int n = 0u;
            char **ne;
            unsigned char *no;

            while (environ != (char **)0 && environ[n] != (char *)0)
                n++;
            ne = malloc(((size_t)n + 2u) * sizeof(char *));
            no = malloc((size_t)n + 2u);
            if (ne == (char **)0 || no == (unsigned char *)0) {
                free(s);
                free(ne); /* 双防御：任一为 NULL 时 free 无操作 */
                return -1;
            }
            for (unsigned int i = 0u; i < n; i++) {
                ne[i] = environ[i];
                no[i] = (catos_env_owned != (unsigned char *)0)
                            ? catos_env_owned[i]
                            : 0u;
            }
            ne[n] = s;
            no[n] = 1u;
            ne[n + 1u] = (char *)0;
            no[n + 1u] = 0u;
            free(environ); /* 指针数组本身是本库产物，可安全回收 */
            free(catos_env_owned);
            environ = ne;
            catos_env_owned = no;
            catos_env_cap = n + 2u;
        }
    }
    return 0;
}

int unsetenv(const char *name)
{
    unsigned int nl = catos_env_name_len(name);
    int idx;
    unsigned int n = 0u;

    if (nl == 0u)
        return -1;
    idx = catos_env_find(name, nl);
    if (idx < 0)
        return -1;

    while (environ[n] != (char *)0)
        n++;

    if (catos_env_owned != (unsigned char *)0 && catos_env_owned[idx] != 0u)
        free(environ[idx]);
    /* 左移收拢：终结 NULL 随之移动；数组容量不缩（复用既有分配） */
    for (unsigned int i = (unsigned int)idx; i < n; i++) {
        environ[i] = environ[i + 1u];
        if (catos_env_owned != (unsigned char *)0)
            catos_env_owned[i] =
                (i + 1u < catos_env_cap) ? catos_env_owned[i + 1u] : 0u;
    }
    return 0;
}

int putenv(char *string)
{
    unsigned int nl = 0u;
    int idx;
    unsigned int n;

    if (string == (char *)0 || string[0] == '\0')
        return -1;
    while (string[nl] != '\0' && string[nl] != '=')
        nl++;
    if (string[nl] != '=') /* 必须形如 "NAME=value" */
        return -1;

    idx = catos_env_find(string, nl);
    if (idx >= 0) { /* 顶替同名旧项：旧项若为本库所有则回收 */
        if (catos_env_owned != (unsigned char *)0 &&
            catos_env_owned[idx] != 0u)
            free(environ[idx]);
        environ[idx] = string;
        catos_env_owned[idx] = 0u; /* 新串归调用方，库不负责回收 */
        return 0;
    }

    n = 0u;
    while (environ != (char **)0 && environ[n] != (char *)0)
        n++;
    {
        char **ne = malloc(((size_t)n + 2u) * sizeof(char *));
        unsigned char *no = malloc((size_t)n + 2u);

        if (ne == (char **)0 || no == (unsigned char *)0) {
            free(ne); /* 双防御 */
            free(no);
            return -1;
        }
        for (unsigned int i = 0u; i < n; i++) {
            ne[i] = environ[i];
            no[i] = (catos_env_owned != (unsigned char *)0)
                        ? catos_env_owned[i]
                        : 0u;
        }
        ne[n] = string;
        no[n] = 0u;
        ne[n + 1u] = (char *)0;
        no[n + 1u] = 0u;
        free(environ);
        free(catos_env_owned);
        environ = ne;
        catos_env_owned = no;
        catos_env_cap = n + 2u;
    }
    return 0;
}

char *getenv(const char *name)
{
    unsigned int nl = catos_env_name_len(name);
    int idx;

    if (nl == 0u)
        return (char *)0;
    idx = catos_env_find(name, nl);
    if (idx < 0)
        return (char *)0;
    return environ[idx] + nl + 1u; /* 跳过 "NAME=" 直指值首 */
}

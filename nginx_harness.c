/*
 * nginx_harness.c — Cat-OS ring3 harness for nginx
 *
 * Provides _start entry point, sets up argc/argv/environ, calls nginx's main().
 */
extern int main(int argc, char *const *argv);
extern char **environ;

static char *__env_empty = (char *)0;

__attribute__((noreturn)) void _start(void)
{
    static char arg0[] = "nginx";
    static char arg1[] = "-c";
    static char arg2[] = "/mnt/fat/CONF/NGINX.CNF";
    static char *argv[] = { arg0, arg1, arg2, (void *)0 };
    int argc = 3;

    /* Ensure environ is a valid NULL-terminated array, not raw NULL pointer */
    environ = &__env_empty;

    main(argc, argv);

    /* Should never return */
    for (;;);
}

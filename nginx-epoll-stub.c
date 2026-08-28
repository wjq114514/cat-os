/* Stub: provide linker symbol for ngx_epoll_module when epoll is disabled.
 * The extern in ngx_event.c is unconditional but the code paths are
 * guarded by #if NGX_HAVE_EPOLL — so this definition is never dereferenced. */
typedef struct { int dummy; } ngx_module_t;
ngx_module_t ngx_epoll_module = { 0 };

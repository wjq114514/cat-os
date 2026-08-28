/* Stub out ngx_bpf.h for Cat-OS (no BPF support) */
#ifndef _NGX_BPF_H
#define _NGX_BPF_H
#include <ngx_config.h>
#include <ngx_core.h>
#ifndef NGX_HAVE_BPF
#define NGX_HAVE_BPF 0
#endif
#endif

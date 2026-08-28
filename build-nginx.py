#!/usr/bin/env python3
"""
Build nginx for Cat-OS i686 from scratch.
Generates a clean Makefile with only the needed source files.
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NGINX = str(ROOT / "nginx-1.26.2")
SHIM  = str(ROOT / "nginx-shim")
LIBC  = str(ROOT)
EPOLL_STUB_SRC = f"{LIBC}/nginx-epoll-stub.c"
EPOLL_STUB_OBJ = f"{NGINX}/objs/nginx_epoll_stub.o"

CC = "i686-linux-gnu-gcc"
CFLAGS = (
    "-pipe -O2 -W -Wall -Wpointer-arith -Wno-unused-parameter "
    "-Wno-sign-compare -Wno-unused-function -Wno-unused-variable "
    "-Wno-unused-but-set-variable -Wno-missing-field-initializers "
    "-Wno-type-limits -Wno-overflow -Wno-implicit-function-declaration -Wno-int-conversion -g "
    "-ffreestanding -nostdlib -nostartfiles -nostdinc -static -m32 "
    f"-I {SHIM} -I /usr/lib/gcc-cross/i686-linux-gnu/13/include -I {LIBC}/libc "
    "-I src/core -I src/event -I src/event/modules -I src/event/quic "
    "-I src/os/unix -I objs -I src/http -I src/http/modules"
)

# Source files we need (no bpf, no epoll)
CORE_SRCS = [
    "objs/ngx_modules.c", "src/core/nginx.c", "src/core/ngx_log.c", "src/core/ngx_palloc.c",
    "src/core/ngx_array.c", "src/core/ngx_list.c", "src/core/ngx_hash.c",
    "src/core/ngx_buf.c", "src/core/ngx_queue.c", "src/core/ngx_output_chain.c",
    "src/core/ngx_string.c", "src/core/ngx_parse.c", "src/core/ngx_parse_time.c",
    "src/core/ngx_inet.c", "src/core/ngx_file.c", "src/core/ngx_crc32.c",
    "src/core/ngx_murmurhash.c", "src/core/ngx_md5.c", "src/core/ngx_sha1.c",
    "src/core/ngx_rbtree.c", "src/core/ngx_radix_tree.c", "src/core/ngx_slab.c",
    "src/core/ngx_times.c", "src/core/ngx_shmtx.c", "src/core/ngx_connection.c",
    "src/core/ngx_cycle.c", "src/core/ngx_spinlock.c", "src/core/ngx_rwlock.c",
    "src/core/ngx_cpuinfo.c", "src/core/ngx_conf_file.c", "src/core/ngx_module.c",
    "src/core/ngx_resolver.c", "src/core/ngx_open_file_cache.c",
    "src/core/ngx_crypt.c", "src/core/ngx_proxy_protocol.c", "src/core/ngx_syslog.c",
]

EVENT_SRCS = [
    "src/event/ngx_event.c", "src/event/ngx_event_timer.c",
    "src/event/ngx_event_posted.c", "src/event/ngx_event_accept.c",
    "src/event/ngx_event_udp.c", "src/event/ngx_event_connect.c",
    "src/event/ngx_event_pipe.c",
    "src/event/modules/ngx_poll_module.c",
]

OS_SRCS = [
    "src/os/unix/ngx_time.c", "src/os/unix/ngx_errno.c",
    "src/os/unix/ngx_alloc.c", "src/os/unix/ngx_files.c",
    "src/os/unix/ngx_socket.c", "src/os/unix/ngx_recv.c",
    "src/os/unix/ngx_readv_chain.c", "src/os/unix/ngx_udp_recv.c",
    "src/os/unix/ngx_send.c", "src/os/unix/ngx_writev_chain.c",
    "src/os/unix/ngx_udp_send.c", "src/os/unix/ngx_udp_sendmsg_chain.c",
    "src/os/unix/ngx_channel.c", "src/os/unix/ngx_shmem.c",
    "src/os/unix/ngx_process.c", "src/os/unix/ngx_daemon.c",
    "src/os/unix/ngx_setaffinity.c", "src/os/unix/ngx_setproctitle.c",
    "src/os/unix/ngx_posix_init.c", "src/os/unix/ngx_user.c",
    "src/os/unix/ngx_dlopen.c", "src/os/unix/ngx_process_cycle.c",
    "src/os/unix/ngx_linux_init.c", "src/os/unix/ngx_linux_sendfile_chain.c",
]

HTTP_SRCS = [
    "src/http/ngx_http.c", "src/http/ngx_http_core_module.c",
    "src/http/ngx_http_special_response.c", "src/http/ngx_http_request.c",
    "src/http/ngx_http_parse.c", "src/http/ngx_http_request_body.c",
    "src/http/ngx_http_variables.c", "src/http/ngx_http_script.c",
    "src/http/ngx_http_write_filter_module.c",
    "src/http/ngx_http_header_filter_module.c",
    "src/http/ngx_http_postpone_filter_module.c",
    "src/http/ngx_http_copy_filter_module.c",
    "src/http/modules/ngx_http_log_module.c",
    "src/http/modules/ngx_http_chunked_filter_module.c",
    "src/http/modules/ngx_http_range_filter_module.c",
    "src/http/modules/ngx_http_headers_filter_module.c",
    "src/http/modules/ngx_http_not_modified_filter_module.c",
    "src/http/modules/ngx_http_static_module.c",
    "src/http/modules/ngx_http_index_module.c",
    "src/http/modules/ngx_http_try_files_module.c",
    "src/http/modules/ngx_http_access_module.c",
    "src/http/modules/ngx_http_empty_gif_module.c",
    "src/http/modules/ngx_http_browser_module.c",
]

ALL_SRCS = CORE_SRCS + EVENT_SRCS + OS_SRCS + HTTP_SRCS
OBJS = ["objs/" + s.replace("/", "_").replace(".c", ".o") for s in ALL_SRCS]

# Generate clean ngx_modules.c (only modules we compile)
MODULES = [
    ("ngx_core_module", "core"),
    ("ngx_errlog_module", "core"),
    ("ngx_conf_module", "core"),
    ("ngx_events_module", "event"),
    ("ngx_event_core_module", "event"),
    ("ngx_poll_module", "event"),
    ("ngx_http_module", "http"),
    ("ngx_http_core_module", "http"),
    ("ngx_http_log_module", "http"),
    ("ngx_http_static_module", "http"),
    ("ngx_http_index_module", "http"),
    ("ngx_http_try_files_module", "http"),
    ("ngx_http_access_module", "http"),
    ("ngx_http_empty_gif_module", "http"),
    ("ngx_http_browser_module", "http"),
    ("ngx_http_write_filter_module", "http"),
    ("ngx_http_header_filter_module", "http"),
    ("ngx_http_chunked_filter_module", "http"),
    ("ngx_http_range_header_filter_module", "http"),
    ("ngx_http_postpone_filter_module", "http"),
    ("ngx_http_headers_filter_module", "http"),
    ("ngx_http_copy_filter_module", "http"),
    ("ngx_http_range_body_filter_module", "http"),
    ("ngx_http_not_modified_filter_module", "http"),
]

ngx_mod_c = [
    "",
    "#include <ngx_config.h>",
    "#include <ngx_core.h>",
    "",
]
for name, _ in MODULES:
    ngx_mod_c.append(f"extern ngx_module_t  {name};")
ngx_mod_c.append("")
ngx_mod_c.append("ngx_module_t *ngx_modules[] = {")
for name, _ in MODULES:
    ngx_mod_c.append(f"    &{name},")
ngx_mod_c.append("    NULL")
ngx_mod_c.append("};")
ngx_mod_c.append("")
ngx_mod_c.append("char *ngx_module_names[] = {")
for name, _ in MODULES:
    ngx_mod_c.append(f'    "{name}",')
ngx_mod_c.append("    NULL")
ngx_mod_c.append("};")
ngx_mod_c.append("")

with open(f"{NGINX}/objs/ngx_modules.c", "w") as f:
    f.write("\n".join(ngx_mod_c))
print(f"Generated ngx_modules.c with {len(MODULES)} modules")

# Build the disabled epoll module definition inside the generated build tree.
# ngx_event.c keeps an unconditional extern for ngx_epoll_module even though
# Cat-OS selects poll at configure time.
stub_cmd = [
    CC, "-c", "-ffreestanding", "-nostdlib", "-nostartfiles", "-nostdinc",
    "-m32", "-o", EPOLL_STUB_OBJ, EPOLL_STUB_SRC,
]
stub_result = subprocess.run(stub_cmd, capture_output=True, text=True, timeout=30)
if stub_result.returncode != 0:
    print("epoll stub compile failed:", stub_result.stderr[-2000:])
    raise SystemExit(f"EPOLL STUB BUILD FAILED (exit {stub_result.returncode})")
print(f"Built local epoll stub: {EPOLL_STUB_OBJ}")

# Generate Makefile
mf_lines = [
    f"CC = {CC}",
    f"CFLAGS = {CFLAGS}",
    "LINK = $(CC)",
    "",
    "build: objs/nginx",
    "",
    f"objs/nginx: {' '.join(OBJS)}",
    f"\t$(LINK) -o objs/nginx -nostdlib -nostartfiles -no-pie -Wl,--whole-archive {LIBC}/libc/libc.a -Wl,--no-whole-archive {EPOLL_STUB_OBJ} /usr/lib/gcc-cross/i686-linux-gnu/13/libgcc.a {' '.join(OBJS)}",
    "",
]

for src, obj in zip(ALL_SRCS, OBJS):
    # Determine deps category
    if src.startswith("src/http"):
        extra_deps = " $(HTTP_DEPS)"
        extra_incs = " $(HTTP_INCS)"
    else:
        extra_deps = ""
        extra_incs = ""

    mf_lines.append(f"{obj}: $(CORE_DEPS){extra_deps} \\")
    mf_lines.append(f"\t{src}")
    mf_lines.append(f"\t$(CC) -c $(CFLAGS) $(CORE_INCS){extra_incs} \\")
    mf_lines.append(f"\t\t-o {obj} \\")
    mf_lines.append(f"\t\t{src}")
    mf_lines.append("")

mf_lines.append("clean:")
mf_lines.append("\trm -rf objs")

with open(f"{NGINX}/objs/Makefile", "w") as f:
    f.write("\n".join(mf_lines) + "\n")

print(f"Custom Makefile generated with {len(ALL_SRCS)} source files")
print("Building...")

result = subprocess.run(
    ["make", "-j4", "-f", "objs/Makefile"],
    cwd=NGINX,
    capture_output=True, text=True, timeout=300
)

print(result.stdout[-2000:] if result.stdout else "")
if result.returncode != 0:
    print("STDERR:", result.stderr[-3000:] if result.stderr else "")
    raise SystemExit(f"BUILD FAILED (exit {result.returncode})")
else:
    print("BUILD SUCCEEDED!")
    r = subprocess.run(["file", f"{NGINX}/objs/nginx"], capture_output=True, text=True)
    print(r.stdout)

    # Now compile the harness and produce final nginx.elf
    print("\n=== Compiling harness and producing nginx.elf ===")

    # Compile harness
    harness_cmd = [
        CC, "-c", "-pipe", "-O2",
        "-ffreestanding", "-nostdlib", "-nostartfiles", "-nostdinc", "-static", "-m32",
        f"-I {SHIM}", f"-I /usr/lib/gcc-cross/i686-linux-gnu/13/include", f"-I {LIBC}/libc",
        "-o", f"{NGINX}/objs/nginx_harness.o",
        f"{LIBC}/nginx_harness.c"
    ]
    r = subprocess.run(harness_cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        print("Harness compile failed:", r.stderr[-1000:])
        raise SystemExit(f"HARNESS BUILD FAILED (exit {r.returncode})")
    else:
        # Link final ELF with harness as entry
        link_cmd = [
            CC, "-o", f"{NGINX}/objs/nginx.elf",
            "-nostdlib", "-nostartfiles", "-no-pie",
            "-e", "_start",
            f"{NGINX}/objs/nginx_harness.o",
            EPOLL_STUB_OBJ,
            "-Wl,--whole-archive", f"{LIBC}/libc/libc.a",
            "-Wl,--no-whole-archive",
            "/usr/lib/gcc-cross/i686-linux-gnu/13/libgcc.a",
        ] + [f"{NGINX}/{o}" for o in OBJS]
        r = subprocess.run(link_cmd, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            print("Link failed:", r.stderr[-1000:])
            raise SystemExit(f"NGINX ELF LINK FAILED (exit {r.returncode})")
        else:
            # Strip
            subprocess.run(["i686-linux-gnu-strip", f"{NGINX}/objs/nginx.elf",
                           "-o", f"{NGINX}/objs/nginx.elf.stripped"], timeout=10)
            r = subprocess.run(["file", f"{NGINX}/objs/nginx.elf"], capture_output=True, text=True)
            print(r.stdout)
            r2 = subprocess.run(["ls", "-la", f"{NGINX}/objs/nginx.elf.stripped"],
                                capture_output=True, text=True)
            print(r2.stdout)
            print("\n=== nginx.elf ready for embedding ===")

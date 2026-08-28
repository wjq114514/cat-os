#!/usr/bin/env python3
"""Patch ngx_auto_headers.h for Cat-OS i686."""

from pathlib import Path

headers = """\
#ifndef NGX_HAVE_UNISTD_H
#define NGX_HAVE_UNISTD_H  1
#endif

#ifndef NGX_HAVE_INTTYPES_H
#define NGX_HAVE_INTTYPES_H  1
#endif

#ifndef NGX_HAVE_LIMITS_H
#define NGX_HAVE_LIMITS_H  1
#endif

#undef NGX_HAVE_SYS_PARAM_H
#undef NGX_HAVE_SYS_MOUNT_H
#undef NGX_HAVE_SYS_STATVFS_H
#undef NGX_HAVE_CRYPT_H

#ifndef NGX_LINUX
#define NGX_LINUX  1
#endif

#undef NGX_HAVE_SYS_PRCTL_H
#undef NGX_HAVE_SYS_VFS_H
"""

path = Path(__file__).resolve().parent / "nginx-1.26.2" / "objs" / "ngx_auto_headers.h"
path.write_text(headers)
print("ngx_auto_headers.h patched")

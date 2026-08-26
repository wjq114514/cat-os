AS      = nasm
CC      = gcc
LD      = ld
OBJCOPY = objcopy
QEMU    = qemu-system-x86_64

CFLAGS  = -m32 -march=i686 -ffreestanding -fno-pic -fno-pie \
          -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables \
          -fno-unwind-tables -nostdlib -Wall -Wextra -std=gnu99 -O2
LDFLAGS = -m elf_i386 -T linker.ld -nostdlib
QEMUFLAGS = -cdrom os.iso -m 128M -display none -serial stdio -no-reboot -no-shutdown \
            -netdev user,id=net0 -device e1000,netdev=net0

OBJS = boot.o arch.o kernel.o paging.o interrupts.o syscall.o process.o netring.o pci.o e1000.o keyboard.o kbdwait.o ide.o rtc.o usermode.o vfs.o net.o \
      elf.o # elf.o(code2): exec syscall 链接 elf_load 所需（elf.c 属其他代理实现）

all: shell_bin.h sock_abi_bin.h os.iso

os.iso: cat-os.bin grub/grub.cfg
	rm -rf iso
	mkdir -p iso/boot/grub
	cp cat-os.bin iso/boot/
	cp grub/grub.cfg iso/boot/grub/
	grub-mkrescue -o $@ iso 2>/dev/null

cat-os.elf: $(OBJS) linker.ld
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

cat-os.bin: cat-os.elf
	$(OBJCOPY) -O binary $< $@

boot.o: boot.asm
	$(AS) -f elf32 -o $@ $<

arch.o: arch.asm
	$(AS) -f elf32 -o $@ $<

%.o: %.c kernel.h paging.h multiboot.h net.h e1000.h shell_bin.h sock_abi_bin.h
	$(CC) $(CFLAGS) -c -o $@ $<

run: os.iso
	$(QEMU) $(QEMUFLAGS)

check: os.iso
	timeout 8s $(QEMU) $(QEMUFLAGS) || test $$? -eq 124

clean:
	rm -rf *.o cat-os.elf cat-os.bin os.iso iso
	rm -f shell_user.elf shell_user.bin shell_bin.h
	rm -f sock_abi.elf sock_abi.bin sock_abi_bin.h sock_abi.o

# ── code2: ring3 shell（shell_user.elf → shell_user.bin → shell_bin.h）───────
# 与内核 CFLAGS 同族，另加 -fcf-protection=none：抑制 .note.gnu.property，
# 保证产物为纯净 ELF32（elf_load 仅认 PT_LOAD 段）。
SHELL_CFLAGS  = -m32 -march=i686 -ffreestanding -fno-pic -fno-pie \
                -fcf-protection=none -fno-stack-protector -fno-builtin \
                -fno-asynchronous-unwind-tables -fno-unwind-tables \
                -nostdlib -Wall -Wextra -std=gnu99 -O2
# 默认链接脚本 + -Ttext=0x400000：entry 恰落用户区下限；其前置 RO LOAD 段
# (0x3ff000) 亦满足 elf_load 的 vaddr>=0x1000 校验（elf.c:150）。
SHELL_LDFLAGS = -m elf_i386 -nostdlib -static -e _start -Ttext=0x400000

shell_user.o: shell_user.c
	$(CC) $(SHELL_CFLAGS) -c -o $@ $<

shell_user.elf: shell_user.o
	$(LD) $(SHELL_LDFLAGS) -o $@ $<

# 扁平镜像（objcopy 提取；供尺寸核对/未来 flat loader，非 elf_load 输入）
shell_user.bin: shell_user.elf
	$(OBJCOPY) -O binary $< $@

# 内嵌头：嵌入完整 ELF（xxd -i 由文件名派生数组名 shell_user_elf/_len，
# 与 syscall.c 的 weak extern 逐字一致）。不用 .bin 作输入的原因：
# elf_load 校验 \x7f"ELF" 魔数，扁平镜像无法通过 —— 见 shell_bin.h 头注释。
shell_bin.h: shell_user.elf shell_user.bin
	xxd -i shell_user.elf > $@.tmp
	{ printf '/*\n * shell_bin.h —— 自动生成：ring3 shell 的 ELF32 镜像内嵌数组（code2 · 并行任务）\n * ⚠️ 请勿手改：由 Makefile 目标 shell_bin.h 重新生成。\n *\n * 内容：shell_user.elf 全文（ELF32 i386 LSB ET_EXEC，入口 _start=0x400000），\n * 而非 objcopy -O binary 的扁平镜像 —— 内核侧唯一加载契约是\n * elf_load(const void *image, size_t len, uint32_t *entry_out)（elf.h），\n * 其第一步即校验 \\x7f"ELF" 魔数（elf.c e_ident 检查链），扁平 bin 无法通过。\n * 扁平产物 shell_user.bin 仍由上一目标独立产出（尺寸/烧写用途）。\n *\n * 内核引用方式（kernel.c 解锁后）：#include "shell_bin.h"，之后\n * exec("/bin/shell") 命中 syscall.c sys_exec 的嵌入镜像分支。\n * 在 kernel.c 尚未 include 本头文件期间，syscall.c 以 weak extern 引用，\n * 符号缺失时运行时判空返回 VFS 分支错误码，不影响链接。\n */\n#ifndef CATOS_SHELL_BIN_H\n#define CATOS_SHELL_BIN_H\n#include <stdint.h>\n'; cat $@.tmp; printf '\n#endif /* CATOS_SHELL_BIN_H */\n'; } > $@ && rm -f $@.tmp

# ── stage4: sock_abi 测试程序（tests/user_sock_abi → 内嵌 ELF，模式同 code2）──
# 与 SHELL_CFLAGS 同族；测试代码含边界用例，定向豁免部分告警。
SOCKABI_CFLAGS  = $(SHELL_CFLAGS) -Ilibc/include                   -Wno-unused-parameter -Wno-unused-variable                   -Wno-sign-compare -Wno-unused-function
SOCKABI_LDFLAGS = $(SHELL_LDFLAGS)

sock_abi.o: tests/user_sock_abi/user_sock_abi_test.c
	$(CC) $(SOCKABI_CFLAGS) -c -o $@ $<

sock_abi.elf: sock_abi.o
	$(LD) $(SOCKABI_LDFLAGS) -o $@ $<

sock_abi.bin: sock_abi.elf
	$(OBJCOPY) -O binary $< $@

# 内嵌头：嵌入完整 ELF（xxd 数组名 sock_abi_elf/_len 与 weak extern 逐字一致）
sock_abi_bin.h: sock_abi.elf sock_abi.bin
	xxd -i sock_abi.elf > $@.tmp
	{ printf '/*\n * sock_abi_bin.h —— 自动生成：stage4 sock_abi 测试 ELF32 内嵌数组\n * ⚠️ 请勿手改：由 Makefile 目标 sock_abi_bin.h 重新生成。\n * 内容：sock_abi_test.elf 全文（ELF32 i386 LSB ET_EXEC），加载契约同 shell_bin.h。\n */\n#ifndef CATOS_SOCK_ABI_BIN_H\n#define CATOS_SOCK_ABI_BIN_H\n#include <stdint.h>\n'; cat $@.tmp; printf '\n#endif /* CATOS_SOCK_ABI_BIN_H */\n'; } > $@ && rm -f $@.tmp


.PHONY: all run check clean

# ── code9: 最小用户态 libc（libc/ 全新目录，零冲突追加；不动上方任何规则）──
# 自检命令族（任务书）：gcc -m32 -ffreestanding -fno-builtin -nostdlib -c；
# 另加与 SHELL_CFLAGS 同族的告警/代码生成开关。头文件自洽，无系统 include。
LIBC_DIR    = libc
LIBC_INC    = $(LIBC_DIR)/include
AR         ?= ar
LIBC_CFLAGS = -m32 -march=i686 -ffreestanding -fno-builtin -nostdlib \
              -fno-pic -fno-pie -fcf-protection=none -fno-stack-protector \
              -fno-asynchronous-unwind-tables -fno-unwind-tables \
              -Wall -Wextra -std=gnu99 -O2 -I$(LIBC_INC)

LIBC_SRCS = $(LIBC_DIR)/src/string.c $(LIBC_DIR)/src/stdio.c \
            $(LIBC_DIR)/src/stdlib.c $(LIBC_DIR)/src/environ.c \
            $(LIBC_DIR)/src/ctype.c $(LIBC_DIR)/src/errno.c
LIBC_OBJS = $(LIBC_SRCS:.c=.o)
LIBC_HDRS = $(wildcard $(LIBC_INC)/*.h) $(LIBC_DIR)/src/catos_syscall.h

$(LIBC_DIR)/src/%.o: $(LIBC_DIR)/src/%.c $(LIBC_HDRS)
	$(CC) $(LIBC_CFLAGS) -c -o $@ $<

# 静态归档：ring3 程序按需拉取成员（shell_user 接入方式见 libc/README.md）
$(LIBC_DIR)/libc.a: $(LIBC_OBJS)
	$(AR) rcs $@ $(LIBC_OBJS)

# ring3 冒烟测试 ELF：链接布局契约同 shell_user（-Ttext=0x400000，_start 入口）
# 测试代码有意触发边界用例（NULL %%s、双重 free、尾随 %% 等），定向豁免告警
LIBC_TEST_CFLAGS = $(LIBC_CFLAGS) -Wno-format -Wno-format-overflow \
                   -Wno-nonnull -Wno-use-after-free -Wno-free-nonheap-object \
                   -Wno-alloc-size-larger-than

$(LIBC_DIR)/tests/smoke_test.o: $(LIBC_DIR)/tests/smoke_test.c $(LIBC_HDRS)
	$(CC) $(LIBC_TEST_CFLAGS) -c -o $@ $<

$(LIBC_DIR)/tests/smoke_test.elf: $(LIBC_DIR)/tests/smoke_test.o $(LIBC_DIR)/libc.a
	$(LD) -m elf_i386 -nostdlib -static -e _start -Ttext=0x400000 -o $@ $^

# 宿主机逻辑单测（不进 ring3 产物；强符号覆盖 catos_stdout_emit 捕获输出）。
# 裸机链接（无系统 crt/libgcc）：host_test 自带 _start，经 Linux i386 ABI
# int 0x80 nr=1 直接退出 —— 同时实证 libc 本体零 libgcc 依赖。
$(LIBC_DIR)/tests/host_test.o: $(LIBC_DIR)/tests/host_test.c $(LIBC_HDRS)
	$(CC) $(LIBC_TEST_CFLAGS) -c -o $@ $<

$(LIBC_DIR)/tests/host_test: $(LIBC_DIR)/tests/host_test.o $(LIBC_OBJS)
	$(LD) -m elf_i386 -nostdlib -static -e _start -o $@ $^

.PHONY: libc-check libc-test libc-clean
libc-check: $(LIBC_DIR)/libc.a $(LIBC_DIR)/tests/smoke_test.elf $(LIBC_DIR)/tests/host_test
libc-test: libc-check
	./$(LIBC_DIR)/tests/host_test && echo "[OK] host unit test EXIT=0"
libc-clean:
	rm -f $(LIBC_OBJS) $(LIBC_DIR)/libc.a $(LIBC_DIR)/tests/smoke_test.o \
	      $(LIBC_DIR)/tests/host_test.o \
	      $(LIBC_DIR)/tests/smoke_test.elf $(LIBC_DIR)/tests/host_test

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

OBJS = boot.o arch.o kernel.o paging.o interrupts.o syscall.o process.o netring.o pci.o e1000.o keyboard.o kbdwait.o ide.o rtc.o usermode.o vfs.o net.o

all: os.iso

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

%.o: %.c kernel.h paging.h multiboot.h net.h e1000.h
	$(CC) $(CFLAGS) -c -o $@ $<

run: os.iso
	$(QEMU) $(QEMUFLAGS)

check: os.iso
	timeout 8s $(QEMU) $(QEMUFLAGS) || test $$? -eq 124

clean:
	rm -rf *.o cat-os.elf cat-os.bin os.iso iso

.PHONY: all run check clean

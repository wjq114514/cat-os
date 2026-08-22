# cat-OS higher-half i686 kernel

This tree boots as a 32-bit Multiboot1 kernel and moves the C kernel into the
higher half at `0xC0000000`.  The flat boot image is still loaded by GRUB at physical
`1MiB`; the linker places `.text` at virtual `0xC0100000`, i.e.
`KERNEL_VIRT_BASE + KERNEL_PHYS_LOAD`.

## Boot sequence

1. GRUB loads the Multiboot raw image at physical `0x00100000` using the
   address fields in the Multiboot header, then enters
   `_start_phys = _start - 0xC0000000` with paging disabled.  `cat-os.elf` is
   kept as a symbol/debug artifact; `cat-os.bin` is the booted flat image.
2. `boot.asm` saves the Multiboot magic and info pointer, initializes COM1, and
   uses a temporary low stack.
3. `boot.asm` builds a bootstrap page directory with two 4MiB PDEs:
   - `0x00000000..0x003fffff -> 0x00000000..0x003fffff` for the current low EIP;
   - `0xC0000000..0xC03fffff -> 0x00000000..0x003fffff` for the kernel alias.
4. It enables `CR4.PSE`, loads `CR3`, sets `CR0.PG`, then performs an absolute
   jump to the higher-half label.
5. The higher-half entry switches to a higher-half stack and calls
   `kernel_main(magic, mbi_phys)`.  All C code executes at high virtual
   addresses.
6. `paging_init()` parses the Multiboot memory map, initializes a tiny
   bitmap/next-fit physical page allocator, creates the final kernel page
   directory, and reloads `CR3`.  The final map keeps a Linux-like `3G/1G`
   layout: physical RAM is directly mapped at `0xC0000000`, while the low
   identity map is removed.
7. `ioremap()` uses normal 4KiB page tables under `0xF0000000` for MMIO.  The
   VGA text buffer is mapped through this window as an early smoke test.

## Memory-management interfaces

- Page-table flags use Linux-style names such as `_PAGE_PRESENT`, `_PAGE_RW`,
  `_PAGE_USER`, `_PAGE_PWT`, `_PAGE_PCD`, `_PAGE_PSE`, and `_PAGE_GLOBAL`.
- `map_page(virt, phys, flags)` creates 4KiB mappings on demand and allocates
  page-table pages via the PMM.
- `pmm_alloc_page()` returns normal page frames from Multiboot usable memory.
- `pmm_alloc_dma_page()` is constrained to the ISA/DMA-safe `<16MiB` zone, a
  placeholder for later NIC descriptor/ring allocation policies.
- `ioremap(phys, size, flags)` reserves virtual space in the MMIO window and
  maps uncached device memory.

The current implementation is intentionally single-core i686 and compact.  It
uses 4MiB PSE leaves for the kernel direct map, and 4KiB page tables for dynamic
mappings, leaving room to evolve toward buddy zones, per-CPU caches, DMA pools,
and low-latency network-buffer allocation.

## Build and run

The current stage adds freestanding interfaces for GDT/IDT exception entry,
native and Linux-shim syscall dispatch (unsupported calls return `-ENOSYS`), a
minimal process/address-space object, and a fixed-size shared network queue
with submit/complete indices, doorbell and busy-poll fields.  The Linux shim
does not claim mmap/futex/epoll/sendmmsg/recvmmsg support yet.

Interrupt setup now loads the kernel IDT with `lidt`. Because the final page
directory removes GRUB's low identity mapping, the boot GDT is copied verbatim
to higher-half resident memory and reloaded with `lgdt`; its descriptors and
runtime `CS` selector are preserved rather than guessed or replaced. The
8259A is remapped to IRQ vectors `0x20-0x2F`; all lines except timer IRQ0 are
masked. PIT channel 0 is programmed for 100 Hz. IRQ delivery remains an early
integration point. QEMU verification covers a recoverable `int3` and PIT IRQ0
delivery through vector 32, including the first three 100 Hz ticks. Additional
device IRQs, spurious IRQ7/15 handling, SMP/APIC and user-mode TSS switching are
not implemented yet.

```sh
make clean
make
make check   # runs QEMU for 8s and accepts timeout as success
make run     # interactive serial log on stdio
```

## IRQ and PCI foundations

## VFS

The VFS layer provides `inode`/`file` objects, per-process-style fd tables,
`file_ops` read/write/close callbacks, and a devfs node set: `/dev/null`,
`/dev/console`, `/dev/kbd`, `/dev/zero`, and `/dev/urandom`. Linux syscall
numbers 5/3/0/1 are routed through the VFS shim. Filesystem registration and
tmpfs-style flat-name storage remain extension points; current fd tables are
kernel-global until process objects gain ownership.

Legacy IRQs use a 16-entry callback table. Drivers call
`irq_register_handler(irq, handler, arg)` and `irq_unregister_handler(irq)`;
handlers return `true` when handled. Unhandled lines warn once. IRQ7/IRQ15 are
checked against the 8259A ISR so spurious interrupts are not dispatched. The
100 Hz PIT is the first table-driven handler.

PCI mechanism #1 is available through `pci_read_config()`,
`pci_write_config()`, and `pci_find_class()`. Boot scans buses 0-2, handles
multifunction devices, and prints identity, class, and BAR resources. QEMU uses
`-netdev user,id=net0 -device e1000,netdev=net0`; its `8086:100e` BAR0 is sized
and mapped with `ioremap`. Limitations are legacy config I/O, no recursive
bridge scan, MSI/MSI-X, 64-bit BAR pairing, resource allocation, or NIC reset.

## e1000 bring-up

`e1000.c` now performs the 82540EM reset/link setup, EERD MAC read, PCI bus
master enable, fixed 8-entry RX/TX rings, 2 KiB receive buffers, RCTL/TCTL
programming, and IRQ11 registration. Descriptor and buffer pages come from the
PMM and device-visible fields contain physical addresses; the polling path
recycles completed RX buffers without per-packet allocation. QEMU is launched
with `-netdev user,id=net0 -device e1000,netdev=net0`.

The current smoke test verifies MAC, ring, link and PIT stability. A guest IP
stack/ARP responder is not present yet, so host `ping 10.0.2.15` cannot be
answered by the kernel and RX completion requires externally injected traffic.
The next step is a minimal ARP request/reply path followed by TX descriptor
completion and an IRQ-driven RX drain.

The minimal ARP path is now present in `e1000.c`: Ethernet ARP requests for
10.0.2.15 are decoded from the fixed RX pool and a 42-byte Ethernet/ARP reply
is submitted through the next preallocated TX descriptor. The TX path uses
the descriptor command `EOP|IFCS|RS` and advances TDT. A full QEMU user-mode
network requires an externally injected packet; the kernel has no general IP
stack or DHCP client yet.

For deterministic RX/TX verification, use QEMU's socket backend instead of
slirp (which handles ARP internally):

```sh
qemu-system-i386 -cdrom os.iso -m 128M -display none -serial stdio \
  -no-reboot -no-shutdown \
  -netdev socket,id=net0,listen=127.0.0.1:12345 \
  -device e1000,netdev=net0
python3 tools/inject.py
```

The injector sends a length-prefixed 42-byte ARP request from
`52:54:00:aa:bb:cc` / `192.168.1.1` for `10.0.2.15`. The guest consumes the RX
descriptor, recycles its fixed buffer, and submits an ARP reply through TX.
QEMU's e1000 model does not implement MAC loopback via `RCTL.LBM`, so loopback
is deliberately not part of the test path.

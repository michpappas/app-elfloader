#!/bin/bash
set -e

ARGS="${@}"

sudo qemu-system-x86_64 \
	-netdev bridge,id=en0,br=virbr0 \
	-device virtio-net-pci,netdev=en0 \
	-kernel "workdir/build/elfloader_qemu-x86_64" \
	-nographic -vga none \
	-append "netdev.ip=192.0.1.2/24:192.0.1.1 -- pg_ukc -c wal_level=logical -c wal_sender_timeout=0" \
	-cpu host,+sse,+xsave,+avx,+avx2 -enable-kvm -machine pc,accel=kvm \
	-m 18G \
	-chardev stdio,id=char0,logfile=serial.log,signal=off \
	-serial chardev:char0 \
	-initrd "workdir/build/initramfs-x86_64.cpio" \
	-monitor none $ARGS

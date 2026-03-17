#!/usr/bin/env bash
# Install Alpine Linux into QCOW2 for sandbox use.
# Run this once to create the base image, then use snapshots.
set -euo pipefail

SANDBOX_DIR="$(cd "$(dirname "$0")" && pwd)"
ISO="$SANDBOX_DIR/images/alpine-virt-3.21.3-x86_64.iso"
DISK="$SANDBOX_DIR/images/alpine-base.qcow2"

echo "==> Starting Alpine installer VM (x86_64 via TCG)..."
echo "    Inside the VM:"
echo "    1. Login as 'root' (no password)"
echo "    2. Run: setup-alpine -f /media/cdrom/alpine-answers"
echo "       OR manually: setup-alpine (follow prompts, use 'sda' for disk)"
echo "    3. After install completes: poweroff"
echo ""
echo "    Press Ctrl+A then X to force-quit QEMU if needed."
echo ""

qemu-system-x86_64 \
    -machine q35 \
    -cpu qemu64 \
    -m 512 \
    -smp 2 \
    -nographic \
    -cdrom "$ISO" \
    -drive file="$DISK",format=qcow2,if=virtio \
    -netdev user,id=net0,restrict=on \
    -device virtio-net-pci,netdev=net0 \
    -boot d

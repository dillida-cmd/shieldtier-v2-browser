#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ShieldTier — Windows Sandbox VM Setup
#
# Downloads a free Windows evaluation image and prepares it for malware
# analysis. Microsoft provides 90-day evaluation VMs at no cost.
#
# Options (pick one):
#   1. Windows 11 Dev Environment (pre-built, ~20GB) — easiest
#   2. Windows 10 Enterprise Eval ISO (~5GB) — most flexible
#   3. Windows Server 2022 Eval ISO (~5GB) — lightest
# ---------------------------------------------------------------------------
set -euo pipefail

SANDBOX_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGES_DIR="$SANDBOX_DIR/images"
mkdir -p "$IMAGES_DIR"

echo "=================================================="
echo "  ShieldTier — Windows Sandbox VM Setup"
echo "=================================================="
echo ""
echo "Choose a Windows image source:"
echo ""
echo "  1) Windows 11 Enterprise Evaluation ISO (6.2 GB)"
echo "     - 90-day free evaluation from Microsoft"
echo "     - Latest Windows platform — matches real-world targets"
echo "     - Best for: real malware analysis"
echo ""
echo "  2) Windows 11 Dev Environment VM (pre-built, ~20GB)"
echo "     - Pre-installed, no setup required"
echo "     - Includes Visual Studio, WSL2, dev tools"
echo "     - Heavier but fastest to get running"
echo ""
echo "  3) I already have a Windows ISO/QCOW2"
echo "     - Point to your existing image"
echo ""
read -p "Select [1-3]: " CHOICE

case "$CHOICE" in
    1)
        echo ""
        echo "=== Windows 11 Enterprise Evaluation ==="
        echo ""
        echo "Microsoft provides a free 90-day evaluation."
        echo "Visit this URL in your browser:"
        echo ""
        echo "  https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise"
        echo ""
        echo "Download the 64-bit ISO and save it to:"
        echo "  $IMAGES_DIR/windows11-eval.iso"
        echo ""
        read -p "Press Enter after downloading, or Ctrl+C to cancel..."

        ISO="$IMAGES_DIR/windows11-eval.iso"
        if [ ! -f "$ISO" ]; then
            echo "ERROR: ISO not found at $ISO"
            exit 1
        fi

        echo "[+] Creating 60GB QCOW2 disk..."
        qemu-img create -f qcow2 "$IMAGES_DIR/windows11-base.qcow2" 60G

        echo "[+] Launching Windows 11 installer..."
        echo ""
        echo "    Inside the VM installer:"
        echo "    1. Install Windows 11 normally"
        echo "    2. After first boot, open PowerShell as Admin and run:"
        echo "       Set-MpPreference -DisableRealtimeMonitoring \$true"
        echo "       mkdir C:\\ShieldTier"
        echo "    3. Copy sandbox-agent.ps1 to C:\\ShieldTier\\"
        echo "    4. Register auto-start:"
        echo "       \$a = New-ScheduledTaskAction -Execute powershell.exe \\"
        echo "         -Argument '-EP Bypass -File C:\\ShieldTier\\sandbox-agent.ps1'"
        echo "       Register-ScheduledTask -TaskName ShieldTier -Action \$a \\"
        echo "         -Trigger (New-ScheduledTaskTrigger -AtLogOn) -RunLevel Highest"
        echo "    5. Shut down the VM"
        echo ""
        echo "    Press Ctrl+A then X to force-quit QEMU."
        echo ""

        # Windows 11 needs TPM bypass for QEMU install
        # Use registry bypass: Shift+F10 during install, then:
        #   reg add HKLM\SYSTEM\Setup\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1
        #   reg add HKLM\SYSTEM\Setup\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1
        #   reg add HKLM\SYSTEM\Setup\LabConfig /v BypassRAMCheck /t REG_DWORD /d 1

        qemu-system-x86_64 \
            -machine q35,accel=tcg \
            -cpu qemu64,+ssse3,+sse4.1,+sse4.2 \
            -m 4096 \
            -smp 4 \
            -cdrom "$ISO" \
            -drive "file=$IMAGES_DIR/windows11-base.qcow2,format=qcow2" \
            -netdev user,id=net0 \
            -device e1000,netdev=net0 \
            -device qemu-xhci \
            -device usb-kbd \
            -device usb-tablet \
            -vga std \
            -boot d
        ;;

    2)
        echo ""
        echo "=== Windows 11 Dev Environment ==="
        echo ""
        echo "Microsoft provides a pre-built VM image:"
        echo "  https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/"
        echo ""
        echo "Download the 'VMWare' or 'Hyper-V' option and convert to QCOW2:"
        echo ""
        echo "  # For VMWare (.vmdk):"
        echo "  qemu-img convert -f vmdk -O qcow2 WinDev*.vmdk $IMAGES_DIR/windows11-base.qcow2"
        echo ""
        echo "  # For Hyper-V (.vhdx):"
        echo "  qemu-img convert -f vhdx -O qcow2 WinDev*.vhdx $IMAGES_DIR/windows11-base.qcow2"
        echo ""
        echo "After conversion, run this script again with option 3."
        ;;

    3)
        echo ""
        read -p "Path to your Windows ISO or QCOW2: " CUSTOM_PATH
        if [ ! -f "$CUSTOM_PATH" ]; then
            echo "ERROR: File not found: $CUSTOM_PATH"
            exit 1
        fi

        EXT="${CUSTOM_PATH##*.}"
        if [ "$EXT" = "qcow2" ]; then
            echo "[+] Linking QCOW2 image..."
            ln -sf "$CUSTOM_PATH" "$IMAGES_DIR/windows-base.qcow2"
            echo "[+] Done. Base image ready at $IMAGES_DIR/windows-base.qcow2"
        elif [ "$EXT" = "iso" ]; then
            echo "[+] Creating 40GB QCOW2 disk for install..."
            qemu-img create -f qcow2 "$IMAGES_DIR/windows-base.qcow2" 40G
            echo "[+] Launch installer with:"
            echo "    qemu-system-x86_64 -machine q35,accel=tcg -cpu qemu64 -m 4096 -smp 4 \\"
            echo "      -cdrom '$CUSTOM_PATH' \\"
            echo "      -drive file=$IMAGES_DIR/windows-base.qcow2,format=qcow2 \\"
            echo "      -netdev user,id=net0 -device e1000,netdev=net0 -vga std -boot d"
        else
            echo "ERROR: Unsupported format. Use .iso or .qcow2"
            exit 1
        fi
        ;;

    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "=== Post-Install Steps ==="
echo ""
echo "After Windows is installed in the QCOW2, run:"
echo ""
echo "  # Create analysis overlay (base image stays clean)"
echo "  qemu-img create -f qcow2 -b windows-base.qcow2 -F qcow2 analysis.qcow2"
echo ""
echo "  # Boot for analysis (isolated network)"
echo "  qemu-system-x86_64 -machine q35,accel=tcg -cpu qemu64 -m 4096 -smp 4 \\"
echo "    -drive file=analysis.qcow2,format=qcow2 \\"
echo "    -netdev user,id=net0,restrict=on -device e1000,netdev=net0 \\"
echo "    -virtfs local,path=./samples,mount_tag=samples,security_model=mapped-xattr \\"
echo "    -vga std"

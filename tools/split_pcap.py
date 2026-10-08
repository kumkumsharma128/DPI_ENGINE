#!/usr/bin/env python3
"""Splits one .pcap into N smaller files (like a rotating Wireshark capture). Usage: split_pcap.py in.pcap outdir N"""
import os, struct, sys
src, outdir, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
os.makedirs(outdir, exist_ok=True)
data = open(src, "rb").read()
hdr, off, pkts = data[:24], 24, []
while off + 16 <= len(data):
    incl = struct.unpack("<I", data[off + 8:off + 12])[0]
    pkts.append(data[off:off + 16 + incl]); off += 16 + incl
size = -(-len(pkts) // n)
for i in range(n):
    with open(os.path.join(outdir, f"part_{i + 1:03d}.pcap"), "wb") as f:
        f.write(hdr); f.write(b"".join(pkts[i * size:(i + 1) * size]))
print(f"split {len(pkts)} packets into {n} files in {outdir}")

#!/usr/bin/env python3
"""Generates samples/test_dpi.pcap: TLS (SNI), HTTP (Host), and DNS traffic. Pure standard library."""
import random, socket, struct, sys

random.seed(7)
packets = []
ts = 1_700_000_000

def add(frame):
    global ts
    ts += 1
    packets.append(struct.pack("<IIII", ts, random.randint(0, 999999), len(frame), len(frame)) + frame)

def eth(payload, src="001122334455", dst="aabbccddeeff"):
    etype = 0x86DD if payload[0] >> 4 == 6 else 0x0800     # IPv6 or IPv4
    return bytes.fromhex(dst) + bytes.fromhex(src) + struct.pack("!H", etype) + payload

HOP_BY_HOP = False      # set True to put an IPv6 extension header in front of TCP/UDP

def ip(src, dst, proto, payload):
    if ":" in src:                                          # IPv6
        nxt = proto
        if HOP_BY_HOP:
            payload = bytes([proto, 0, 1, 4, 0, 0, 0, 0]) + payload
            nxt = 0
        return (struct.pack("!IHBB", 0x60000000, len(payload), nxt, 64)
                + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), random.randint(0, 65535), 0, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + payload

def tcp(sp, dp, seq, ack, flags, data=b""):
    return struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0) + data

def udp(sp, dp, data):
    return struct.pack("!HHHH", sp, dp, 8 + len(data), 0) + data

SYN, SYNACK, ACK, PSHACK = 0x02, 0x12, 0x10, 0x18

def client_hello(host):
    h = host.encode()
    sni = struct.pack("!HBH", len(h) + 3, 0, len(h)) + h
    exts = struct.pack("!HH", 0, len(sni)) + sni + struct.pack("!HHH", 0x000a, 4, 2) + b"\x00\x1d"[:2]
    exts = struct.pack("!HH", 0, len(sni)) + sni              # keep it simple: only the SNI extension
    body = (b"\x03\x03" + bytes(32) + b"\x00" + struct.pack("!H", 4) + b"\x13\x01\x13\x02" + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs

def https_flow(client, server, host, sport, extra_data=3):
    add(eth(ip(client, server, 6, tcp(sport, 443, 1000, 0, SYN))))
    add(eth(ip(server, client, 6, tcp(443, sport, 5000, 1001, SYNACK))))
    add(eth(ip(client, server, 6, tcp(sport, 443, 1001, 5001, ACK))))
    add(eth(ip(client, server, 6, tcp(sport, 443, 1001, 5001, PSHACK, client_hello(host)))))
    for n in range(extra_data):
        add(eth(ip(server, client, 6, tcp(443, sport, 5001 + n * 200, 1200, PSHACK, bytes(random.getrandbits(8) for _ in range(180))))))
        add(eth(ip(client, server, 6, tcp(sport, 443, 1200 + n * 50, 5200, ACK))))

def http_flow(client, server, host, sport):
    add(eth(ip(client, server, 6, tcp(sport, 80, 1, 0, SYN))))
    add(eth(ip(server, client, 6, tcp(80, sport, 1, 2, SYNACK))))
    add(eth(ip(client, server, 6, tcp(sport, 80, 2, 2, ACK))))
    req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\n\r\n".encode()
    add(eth(ip(client, server, 6, tcp(sport, 80, 2, 2, PSHACK, req))))
    add(eth(ip(server, client, 6, tcp(80, sport, 2, 100, PSHACK, b"HTTP/1.1 200 OK\r\n\r\nhello"))))

def dns_flow(client, resolver, host, sport):
    q = struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(l)]) + l.encode() for l in host.split(".")) + b"\x00" + struct.pack("!HH", 1, 1)
    add(eth(ip(client, resolver, 17, udp(sport, 53, q))))
    r = bytearray(q); r[2:4] = struct.pack("!H", 0x8180)
    add(eth(ip(resolver, client, 17, udp(53, sport, bytes(r)))))

me, friend = "192.168.1.100", "192.168.1.50"
for n, (host, srv) in enumerate([
        ("www.youtube.com", "142.250.185.206"), ("rr3---sn.googlevideo.com", "142.250.185.207"),
        ("www.facebook.com", "157.240.1.35"), ("www.instagram.com", "157.240.1.174"),
        ("www.google.com", "142.250.190.4"), ("github.com", "140.82.112.3"),
        ("www.netflix.com", "54.237.226.164"), ("www.tiktok.com", "161.117.70.40"),
        ("example.org", "93.184.216.34")]):
    https_flow(me, srv, host, 50000 + n)
    dns_flow(me, "8.8.8.8", host, 40000 + n)
http_flow(me, "93.184.216.34", "neverssl.com", 51000)
http_flow(me, "157.240.1.35", "www.facebook.com", 51001)
https_flow(friend, "142.250.185.206", "www.youtube.com", 52000)      # another user (192.168.1.50)
https_flow(friend, "151.101.1.69", "www.reddit.com", 52001)

# ---- IPv6 traffic (most home/mobile networks use it for Google, YouTube, ...) ----
me6 = "2401:4900:1c2a:5b::10"
https_flow(me6, "2404:6800:4009:82a::200e", "www.youtube.com", 53000)
https_flow(me6, "2a03:2880:f12f:83:face:b00c:0:25de", "www.facebook.com", 53001)
dns_flow(me6, "2001:4860:4860::8888", "www.google.com", 41000)
HOP_BY_HOP = True
https_flow(me6, "2404:6800:4007:821::2004", "www.google.com", 53002)
HOP_BY_HOP = False

out = sys.argv[1] if len(sys.argv) > 1 else "samples/test_dpi.pcap"
with open(out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    f.write(b"".join(packets))
print(f"wrote {out}: {len(packets)} packets")

#include "packet_parser.h"
#include <algorithm>

static inline uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
static inline uint32_t be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}

// Layer 4 (TCP / UDP). `l4` points at the transport header, `avail` = bytes left in the IP payload.
static bool parseL4(uint8_t proto, const uint8_t* l4, size_t avail, ParsedPacket& out) {
    out.tuple.proto = proto;
    if (proto == 6) {                                // TCP
        if (avail < 20) return false;
        size_t thl = (l4[12] >> 4) * 4;
        if (thl < 20 || thl > avail) return false;
        out.is_tcp = true;
        out.tuple.src_port = be16(l4);
        out.tuple.dst_port = be16(l4 + 2);
        out.tcp_flags = l4[13];
        out.payload = l4 + thl;
        out.payload_len = avail - thl;
        return true;
    }
    if (proto == 17) {                               // UDP
        if (avail < 8) return false;
        out.is_udp = true;
        out.tuple.src_port = be16(l4);
        out.tuple.dst_port = be16(l4 + 2);
        out.payload = l4 + 8;
        out.payload_len = avail - 8;
        return true;
    }
    return false;                                    // ICMP and others: not handled
}

bool parsePacket(const uint8_t* d, size_t len, ParsedPacket& out) {
    // ---- Layer 2: Ethernet (14 bytes) ----
    if (len < 14) return false;
    uint16_t ethertype = be16(d + 12);
    size_t off = 14;
    if (ethertype == 0x8100) {                       // VLAN tag adds 4 bytes
        if (len < 18) return false;
        ethertype = be16(d + 16);
        off = 18;
    }
    out = ParsedPacket{};

    // ---- Layer 3: IPv4 ----
    if (ethertype == 0x0800) {
        if (len < off + 20) return false;
        const uint8_t* ip = d + off;
        if ((ip[0] >> 4) != 4) return false;
        size_t ihl = (ip[0] & 0x0F) * 4;
        if (ihl < 20 || len < off + ihl) return false;
        size_t total = be16(ip + 2);
        if (total < ihl) return false;
        size_t ip_end = std::min(len, off + total);  // ignores Ethernet padding
        if (be16(ip + 6) & 0x1FFF) return false;     // non-first fragment: no L4 header
        out.tuple.src_ip = IpAddr::fromV4(be32(ip + 12));
        out.tuple.dst_ip = IpAddr::fromV4(be32(ip + 16));
        return parseL4(ip[9], ip + ihl, ip_end - (off + ihl), out);
    }

    // ---- Layer 3: IPv6 (fixed 40-byte header, then optional extension headers) ----
    if (ethertype == 0x86DD) {
        if (len < off + 40) return false;
        const uint8_t* ip6 = d + off;
        if ((ip6[0] >> 4) != 6) return false;
        size_t payload_len = be16(ip6 + 4);
        size_t ip_end = payload_len ? std::min(len, off + 40 + payload_len) : len;
        uint8_t next = ip6[6];
        const uint8_t* p = ip6 + 40;
        size_t avail = ip_end - (off + 40);
        for (int i = 0; i < 8; ++i) {                // walk extension headers (bounded loop)
            if (next == 0 || next == 43 || next == 60) {        // hop-by-hop, routing, destination options
                if (avail < 8) return false;
                size_t hl = (size_t(p[1]) + 1) * 8;
                if (hl > avail) return false;
                next = p[0]; p += hl; avail -= hl;
            } else if (next == 44) {                            // fragment header
                if (avail < 8) return false;
                if (be16(p + 2) & 0xFFF8) return false;         // non-first fragment
                next = p[0]; p += 8; avail -= 8;
            } else break;
        }
        out.tuple.src_ip = IpAddr::fromV6(ip6 + 8);
        out.tuple.dst_ip = IpAddr::fromV6(ip6 + 24);
        return parseL4(next, p, avail, out);
    }
    return false;                                    // ARP and everything else
}

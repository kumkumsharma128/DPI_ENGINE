#pragma once
#include <cstddef>
#include <cstdint>
#include "types.h"

struct ParsedPacket {
    FiveTuple tuple;                 // as seen on the wire (not canonical)
    bool is_tcp = false, is_udp = false;
    uint8_t tcp_flags = 0;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
};

// Parses Ethernet (+optional 802.1Q VLAN) -> IPv4 or IPv6 -> TCP/UDP.
// Returns false for anything else (ARP, ICMP, fragments, truncated packets).
bool parsePacket(const uint8_t* data, size_t len, ParsedPacket& out);

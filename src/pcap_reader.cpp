#include "pcap_reader.h"

static_assert(sizeof(PcapGlobalHeader) == 24, "pcap global header must be 24 bytes");
static_assert(sizeof(PcapPacketHeader) == 16, "pcap packet header must be 16 bytes");

static uint32_t bs32(uint32_t v) {
    return (v >> 24) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | (v << 24);
}
static uint16_t bs16(uint16_t v) { return static_cast<uint16_t>((v >> 8) | (v << 8)); }

bool PcapReader::open(const std::string& path) {
    in_.open(path, std::ios::binary);
    if (!in_) { err_ = "cannot open file: " + path; return false; }
    if (!in_.read(reinterpret_cast<char*>(&gh_), sizeof gh_)) { err_ = "file too short"; return false; }

    switch (gh_.magic) {
        case 0xa1b2c3d4: case 0xa1b23c4d: swap_ = false; break;
        case 0xd4c3b2a1: case 0x4d3cb2a1: swap_ = true; break;
        default: err_ = "not a classic pcap file (pcapng is not supported; save as .pcap)"; return false;
    }
    if (swap_) {
        gh_.magic = bs32(gh_.magic);
        gh_.version_major = bs16(gh_.version_major);
        gh_.version_minor = bs16(gh_.version_minor);
        gh_.thiszone = static_cast<int32_t>(bs32(static_cast<uint32_t>(gh_.thiszone)));
        gh_.sigfigs = bs32(gh_.sigfigs);
        gh_.snaplen = bs32(gh_.snaplen);
        gh_.network = bs32(gh_.network);
    }
    if (gh_.network != 1) { err_ = "only Ethernet (link type 1) captures are supported"; return false; }
    return true;
}

bool PcapReader::next(RawPacket& pkt) {
    if (!in_.read(reinterpret_cast<char*>(&pkt.hdr), sizeof pkt.hdr)) return false;
    if (swap_) {
        pkt.hdr.ts_sec = bs32(pkt.hdr.ts_sec);   pkt.hdr.ts_usec = bs32(pkt.hdr.ts_usec);
        pkt.hdr.incl_len = bs32(pkt.hdr.incl_len); pkt.hdr.orig_len = bs32(pkt.hdr.orig_len);
    }
    if (pkt.hdr.incl_len > 262144) return false;          // corrupt record guard
    pkt.data.resize(pkt.hdr.incl_len);
    return static_cast<bool>(in_.read(reinterpret_cast<char*>(pkt.data.data()), pkt.hdr.incl_len));
}

bool PcapWriter::open(const std::string& path, const PcapGlobalHeader& gh) {
    out_.open(path, std::ios::binary);
    if (!out_) return false;
    out_.write(reinterpret_cast<const char*>(&gh), sizeof gh);   // host byte order + matching magic
    return true;
}
void PcapWriter::write(const RawPacket& pkt) {
    out_.write(reinterpret_cast<const char*>(&pkt.hdr), sizeof pkt.hdr);
    out_.write(reinterpret_cast<const char*>(pkt.data.data()), static_cast<std::streamsize>(pkt.data.size()));
}

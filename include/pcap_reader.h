#pragma once
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

struct PcapGlobalHeader {          // 24 bytes on disk
    uint32_t magic;                // normalized: 0xa1b2c3d4 (us) or 0xa1b23c4d (ns)
    uint16_t version_major, version_minor;
    int32_t  thiszone;
    uint32_t sigfigs, snaplen, network;   // network 1 = Ethernet
};
struct PcapPacketHeader {          // 16 bytes on disk
    uint32_t ts_sec, ts_usec, incl_len, orig_len;
};
struct RawPacket {
    PcapPacketHeader hdr{};
    std::vector<uint8_t> data;
};

class PcapReader {
public:
    bool open(const std::string& path);
    bool next(RawPacket& pkt);     // false at end of file / corrupt record
    const PcapGlobalHeader& header() const { return gh_; }
    const std::string& error() const { return err_; }
private:
    std::ifstream in_;
    PcapGlobalHeader gh_{};
    bool swap_ = false;
    std::string err_;
};

class PcapWriter {
public:
    bool open(const std::string& path, const PcapGlobalHeader& gh);
    void write(const RawPacket& pkt);
private:
    std::ofstream out_;
};

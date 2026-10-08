#include "sni_extractor.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include "types.h"

static inline uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

std::optional<std::string> extractSNI(const uint8_t* d, size_t len) {
    // TLS record header (5 bytes) + handshake header (4 bytes)
    if (len < 9) return std::nullopt;
    if (d[0] != 0x16) return std::nullopt;                  // content type: handshake
    if (d[1] != 0x03) return std::nullopt;                  // TLS major version
    if (d[5] != 0x01) return std::nullopt;                  // handshake type: ClientHello
    size_t end = std::min(len, size_t(5) + be16(d + 3));    // hello may be split across packets

    size_t off = 9 + 2 + 32;                                // skip version(2) + random(32)
    if (off + 1 > end) return std::nullopt;
    off += 1 + d[off];                                      // session id
    if (off + 2 > end) return std::nullopt;
    off += 2 + be16(d + off);                               // cipher suites
    if (off + 1 > end) return std::nullopt;
    off += 1 + d[off];                                      // compression methods
    if (off + 2 > end) return std::nullopt;
    size_t ext_end = std::min(end, off + 2 + be16(d + off));
    off += 2;

    while (off + 4 <= ext_end) {                            // walk extensions
        uint16_t type = be16(d + off), elen = be16(d + off + 2);
        off += 4;
        if (off + elen > ext_end) return std::nullopt;
        if (type == 0x0000) {                               // server_name extension
            if (elen < 5) return std::nullopt;
            uint8_t name_type = d[off + 2];
            uint16_t name_len = be16(d + off + 3);
            if (name_type != 0 || size_t(5) + name_len > elen) return std::nullopt;
            return toLower(std::string(reinterpret_cast<const char*>(d + off + 5), name_len));
        }
        off += elen;
    }
    return std::nullopt;
}

static bool ieq(const char* a, const char* b, size_t n) {   // case-insensitive compare, portable
    for (size_t i = 0; i < n; ++i)
        if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i])) return false;
    return true;
}

std::optional<std::string> extractHttpHost(const uint8_t* p, size_t n) {
    static const char* methods[] = {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "};
    bool is_http = false;
    for (auto m : methods) {
        size_t ml = std::strlen(m);
        if (n >= ml && std::memcmp(p, m, ml) == 0) { is_http = true; break; }
    }
    if (!is_http) return std::nullopt;

    std::string s(reinterpret_cast<const char*>(p), std::min<size_t>(n, 4096));
    size_t pos = 0;
    while (pos < s.size()) {
        size_t e = s.find('\n', pos);
        if (e == std::string::npos) e = s.size();
        if (e - pos >= 5 && ieq(s.c_str() + pos, "host:", 5)) {
            size_t b = pos + 5;
            while (b < e && (s[b] == ' ' || s[b] == '\t')) ++b;
            size_t t = e;
            while (t > b && (s[t - 1] == '\r' || s[t - 1] == ' ')) --t;
            std::string host = s.substr(b, t - b);
            size_t colon = host.find(':');                  // drop :port
            if (colon != std::string::npos) host.resize(colon);
            if (host.empty()) return std::nullopt;
            return toLower(host);
        }
        pos = e + 1;
    }
    return std::nullopt;
}

std::optional<std::string> extractDnsQuery(const uint8_t* p, size_t n) {
    if (n < 17) return std::nullopt;                        // 12-byte header + at least 1 label + type/class
    if (be16(p + 4) < 1) return std::nullopt;               // QDCOUNT
    size_t off = 12;
    std::string name;
    while (true) {
        if (off >= n) return std::nullopt;
        uint8_t l = p[off++];
        if (l == 0) break;
        if (l & 0xC0) return std::nullopt;                  // compression pointer: not expected in a question
        if (off + l > n) return std::nullopt;
        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<const char*>(p + off), l);
        off += l;
        if (name.size() > 253) return std::nullopt;
    }
    if (name.empty()) return std::nullopt;
    return toLower(name);
}

#pragma once
#include <array>
#include <cstdint>
#include <string>

enum class AppType { UNKNOWN = 0, HTTP, HTTPS, DNS, GOOGLE, YOUTUBE, FACEBOOK,
                     INSTAGRAM, NETFLIX, GITHUB, TIKTOK, TWITTER, AMAZON, COUNT };

const char* appName(AppType a);
bool appFromName(const std::string& name, AppType& out);   // case-insensitive
AppType sniToApp(const std::string& domain);                // domain -> app
std::string toLower(std::string s);

// One address type for both IPv4 and IPv6. IPv4 is stored "IPv4-mapped" (::ffff:a.b.c.d),
// so the rest of the program never needs to care which version a packet used.
struct IpAddr {
    std::array<uint8_t, 16> b{};
    static IpAddr fromV4(uint32_t host_order_ip) {
        IpAddr a;
        a.b[10] = a.b[11] = 0xff;
        a.b[12] = host_order_ip >> 24; a.b[13] = host_order_ip >> 16;
        a.b[14] = host_order_ip >> 8;  a.b[15] = host_order_ip;
        return a;
    }
    static IpAddr fromV6(const uint8_t* p) {
        IpAddr a;
        for (int i = 0; i < 16; ++i) a.b[i] = p[i];
        return a;
    }
    bool isV4() const {
        for (int i = 0; i < 10; ++i) if (b[i]) return false;
        return b[10] == 0xff && b[11] == 0xff;
    }
    bool operator==(const IpAddr& o) const { return b == o.b; }
    bool operator<(const IpAddr& o) const { return b < o.b; }
};

std::string ipToString(const IpAddr& ip);                       // "1.2.3.4" or "2001:db8::1"
std::string endpointToString(const IpAddr& ip, uint16_t port);  // "1.2.3.4:443" or "[2001:db8::1]:443"
bool ipFromString(const std::string& s, IpAddr& out);           // accepts IPv4 and IPv6

// A connection is identified by these five values.
struct FiveTuple {
    IpAddr src_ip, dst_ip;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t  proto = 0;

    bool operator==(const FiveTuple& o) const {
        return src_ip == o.src_ip && dst_ip == o.dst_ip && src_port == o.src_port &&
               dst_port == o.dst_port && proto == o.proto;
    }
    // Same key for A->B and B->A, so both directions land in one flow.
    FiveTuple canonical() const {
        if (src_ip < dst_ip || (src_ip == dst_ip && src_port <= dst_port)) return *this;
        FiveTuple t = *this;
        t.src_ip = dst_ip;     t.dst_ip = src_ip;
        t.src_port = dst_port; t.dst_port = src_port;
        return t;
    }
};

struct FiveTupleHash {
    size_t operator()(const FiveTuple& t) const {
        uint64_t h = 1469598103934665603ULL;               // FNV-1a style mixing
        auto mix = [&](uint64_t v) { h ^= v; h *= 1099511628211ULL; };
        for (uint8_t x : t.src_ip.b) mix(x);
        for (uint8_t x : t.dst_ip.b) mix(x);
        mix(t.src_port); mix(t.dst_port); mix(t.proto);
        return static_cast<size_t>(h);
    }
};

struct Flow {
    FiveTuple key;                  // canonical key
    uint64_t packets = 0, bytes = 0;
    AppType app = AppType::UNKNOWN;
    std::string domain;             // SNI, HTTP Host, or DNS query name
    bool blocked = false;
};

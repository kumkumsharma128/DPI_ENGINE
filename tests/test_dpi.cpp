// Minimal self-contained tests (no framework needed). Build with: make test
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include "packet_parser.h"
#include "sni_extractor.h"
#include "sites.h"
#include "types.h"

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { std::printf("FAIL line %d: %s\n", __LINE__, #cond); ++failures; } } while (0)

static void put16(std::vector<uint8_t>& v, unsigned x) { v.push_back(x >> 8); v.push_back(x & 255); }

static std::vector<uint8_t> clientHello(const std::string& host) {
    std::vector<uint8_t> sni;
    put16(sni, host.size() + 3); sni.push_back(0); put16(sni, host.size());
    sni.insert(sni.end(), host.begin(), host.end());
    std::vector<uint8_t> ext; put16(ext, 0); put16(ext, sni.size());
    ext.insert(ext.end(), sni.begin(), sni.end());
    std::vector<uint8_t> body = {3, 3};
    body.insert(body.end(), 32, 0); body.push_back(0);
    put16(body, 4); body.insert(body.end(), {0x13, 1, 0x13, 2}); body.insert(body.end(), {1, 0});
    put16(body, ext.size()); body.insert(body.end(), ext.begin(), ext.end());
    std::vector<uint8_t> hs = {1, 0, 0, 0};
    hs[1] = body.size() >> 16; hs[2] = (body.size() >> 8) & 255; hs[3] = body.size() & 255;
    hs.insert(hs.end(), body.begin(), body.end());
    std::vector<uint8_t> rec = {0x16, 3, 1}; put16(rec, hs.size());
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

int main() {
    // SNI
    auto ch = clientHello("WWW.YouTube.com");
    auto sni = extractSNI(ch.data(), ch.size());
    CHECK(sni && *sni == "www.youtube.com");
    CHECK(!extractSNI(ch.data(), 0));
    // Every truncated prefix must be handled safely (no crash, no garbage)
    for (size_t n = 0; n < ch.size(); ++n) (void)extractSNI(ch.data(), n);
    // Random garbage must never crash
    std::srand(1);
    for (int r = 0; r < 20000; ++r) {
        std::vector<uint8_t> junk(std::rand() % 200);
        for (auto& b : junk) b = std::rand();
        if (!junk.empty() && r % 2) junk[0] = 0x16;
        if (junk.size() > 14 && r % 3 == 0) { junk[12] = 0x86; junk[13] = 0xDD; }   // fuzz the IPv6 path too
        (void)extractSNI(junk.data(), junk.size());
        (void)extractHttpHost(junk.data(), junk.size());
        (void)extractDnsQuery(junk.data(), junk.size());
        ParsedPacket p; (void)parsePacket(junk.data(), junk.size(), p);
    }
    // HTTP
    std::string req = "GET /x HTTP/1.1\r\nhOsT: Example.com:8080\r\nAccept: */*\r\n\r\n";
    auto host = extractHttpHost((const uint8_t*)req.data(), req.size());
    CHECK(host && *host == "example.com");
    std::string notHttp = "hello world";
    CHECK(!extractHttpHost((const uint8_t*)notHttp.data(), notHttp.size()));
    // DNS
    std::vector<uint8_t> dns = {0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
    auto q = extractDnsQuery(dns.data(), dns.size());
    CHECK(q && *q == "www.example.com");
    // App mapping
    CHECK(sniToApp("rr3---sn.googlevideo.com") == AppType::YOUTUBE);
    CHECK(sniToApp("www.google.com") == AppType::GOOGLE);
    CHECK(sniToApp("example.org") == AppType::UNKNOWN);
    // Flow key is direction-independent
    FiveTuple a{IpAddr::fromV4(1), IpAddr::fromV4(2), 1000, 443, 6}, b{IpAddr::fromV4(2), IpAddr::fromV4(1), 443, 1000, 6};
    CHECK(a.canonical() == b.canonical());
    // IP helpers
    IpAddr ip;
    CHECK(ipFromString("192.168.1.50", ip) && ipToString(ip) == "192.168.1.50");
    CHECK(!ipFromString("300.1.1.1", ip));
    CHECK(ipFromString("2001:db8::1", ip) && ipToString(ip) == "2001:db8::1" && !ip.isV4());
    // IPv6 packet WITH a hop-by-hop extension header: Ethernet + IPv6 + ext(8) + TCP + payload
    {
        std::vector<uint8_t> pkt(12, 0); put16(pkt, 0x86DD);
        std::vector<uint8_t> tcp(20, 0); tcp[0] = 0xC3; tcp[1] = 0x50; tcp[2] = 0x01; tcp[3] = 0xBB; tcp[12] = 5 << 4;
        std::vector<uint8_t> ext = {6, 0, 1, 4, 0, 0, 0, 0};
        std::vector<uint8_t> body = ext; body.insert(body.end(), tcp.begin(), tcp.end());
        body.insert(body.end(), {'h', 'i'});
        pkt.insert(pkt.end(), {0x60, 0, 0, 0}); put16(pkt, body.size()); pkt.push_back(0); pkt.push_back(64);
        std::vector<uint8_t> addrs(32, 0); addrs[15] = 1; addrs[31] = 2;
        pkt.insert(pkt.end(), addrs.begin(), addrs.end());
        pkt.insert(pkt.end(), body.begin(), body.end());
        ParsedPacket pp;
        CHECK(parsePacket(pkt.data(), pkt.size(), pp));
        CHECK(pp.is_tcp && pp.tuple.dst_port == 443 && pp.tuple.src_port == 50000);
        CHECK(pp.payload_len == 2 && !pp.tuple.src_ip.isV4());
    }

    // Site summary lookup
    CHECK(lookupSite("media.licdn.com").name == "LinkedIn" && lookupSite("media.licdn.com").cat == Category::SITE);
    CHECK(lookupSite("px.ads.linkedin.com").cat == Category::ADS_TRACKING);          // longest suffix wins
    CHECK(lookupSite("www.linkedin.com").cat == Category::SITE);
    CHECK(lookupSite("mail.google.com").name == "Gmail");
    CHECK(lookupSite("www.google.co.in").name == "Google");
    CHECK(lookupSite("stats.g.doubleclick.net").cat == Category::ADS_TRACKING);
    CHECK(lookupSite("BOX.com").matched == false);                                    // "x.com" must not match "box.com"
    CHECK(lookupSite("something.unknown.example").cat == Category::OTHER);
    CHECK(lookupSite("Fonts.GStatic.com.").cat == Category::ASSETS);                  // case + trailing dot

    std::printf(failures ? "%d test(s) FAILED\n" : "All tests passed\n", failures);
    return failures ? 1 : 0;
}

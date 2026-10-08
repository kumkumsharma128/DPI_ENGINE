#include "types.h"
#include <algorithm>
#include <cctype>
#include <arpa/inet.h>
#include <cstdio>
#include <utility>
#include <vector>

static const char* kNames[] = {"Unknown", "HTTP", "HTTPS", "DNS", "Google", "YouTube",
    "Facebook", "Instagram", "Netflix", "GitHub", "TikTok", "Twitter", "Amazon"};

const char* appName(AppType a) { return kNames[static_cast<int>(a)]; }

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

bool appFromName(const std::string& name, AppType& out) {
    std::string n = toLower(name);
    for (int i = 0; i < static_cast<int>(AppType::COUNT); ++i)
        if (toLower(kNames[i]) == n) { out = static_cast<AppType>(i); return true; }
    return false;
}

AppType sniToApp(const std::string& domain) {
    // Order matters: more specific brands before broader ones (youtube before google).
    static const std::vector<std::pair<const char*, AppType>> table = {
        {"youtube", AppType::YOUTUBE}, {"googlevideo", AppType::YOUTUBE}, {"ytimg", AppType::YOUTUBE},
        {"instagram", AppType::INSTAGRAM}, {"facebook", AppType::FACEBOOK}, {"fbcdn", AppType::FACEBOOK},
        {"netflix", AppType::NETFLIX}, {"nflxvideo", AppType::NETFLIX},
        {"github", AppType::GITHUB}, {"tiktok", AppType::TIKTOK}, {"byteoversea", AppType::TIKTOK},
        {"twitter", AppType::TWITTER}, {"twimg", AppType::TWITTER},
        {"amazon", AppType::AMAZON}, {"google", AppType::GOOGLE}, {"gstatic", AppType::GOOGLE}};
    std::string d = toLower(domain);
    for (auto& [needle, app] : table)
        if (d.find(needle) != std::string::npos) return app;
    return AppType::UNKNOWN;
}

std::string ipToString(const IpAddr& ip) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (ip.isV4()) {
        std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", ip.b[12], ip.b[13], ip.b[14], ip.b[15]);
        return buf;
    }
    if (!inet_ntop(AF_INET6, ip.b.data(), buf, sizeof buf)) return "?";
    return buf;
}

std::string endpointToString(const IpAddr& ip, uint16_t port) {
    std::string a = ipToString(ip);
    return (ip.isV4() ? a : "[" + a + "]") + ":" + std::to_string(port);
}

bool ipFromString(const std::string& s, IpAddr& out) {
    unsigned a, b, c, d; char extra;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) == 4) {
        if (a > 255 || b > 255 || c > 255 || d > 255) return false;
        out = IpAddr::fromV4((a << 24) | (b << 16) | (c << 8) | d);
        return true;
    }
    uint8_t raw[16];
    if (inet_pton(AF_INET6, s.c_str(), raw) == 1) { out = IpAddr::fromV6(raw); return true; }
    return false;
}

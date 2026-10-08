#pragma once
#include <set>
#include <string>
#include <vector>
#include "types.h"

// Flow-level blocking rules. A flow is blocked if ANY rule matches.
struct Rules {
    std::set<AppType> apps;
    std::set<IpAddr> ips;                   // matches either endpoint of the flow
    std::vector<std::string> domains;       // lower-case substrings of SNI / Host / DNS name

    bool empty() const { return apps.empty() && ips.empty() && domains.empty(); }

    bool matches(const Flow& f) const {
        if (ips.count(f.key.src_ip) || ips.count(f.key.dst_ip)) return true;
        if (apps.count(f.app)) return true;
        for (const auto& d : domains)
            if (!f.domain.empty() && f.domain.find(d) != std::string::npos) return true;
        return false;
    }
};

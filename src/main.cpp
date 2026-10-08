// DPI engine v2: multiple files, whole folders, and "watch" mode (near real-time).
//   pcap files -> parse -> flow table (shared across files) -> classify -> rules -> report
#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <thread>
#include <unordered_map>
#include <vector>

#include "packet_parser.h"
#include "pcap_reader.h"
#include "rules.h"
#include "sites.h"
#include "sni_extractor.h"
#include "types.h"

namespace fs = std::filesystem;
using ull = unsigned long long;

static volatile std::sig_atomic_t g_stop = 0;
static void onSigint(int) { g_stop = 1; }

static void usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s <file.pcap | folder> [more files/folders...] [options]\n"
        "  --out <file.pcap>       write filtered packets (only with exactly one input file)\n"
        "  --out-dir <folder>      write <name>.filtered.pcap for every input file\n"
        "  --watch <folder>        keep watching the folder and process new .pcap files (Ctrl+C to stop)\n"
        "  --block-app <name>      e.g. YouTube, Facebook, TikTok\n"
        "  --block-ip <a.b.c.d>    block any flow to/from this IP\n"
        "  --block-domain <text>   block flows whose domain contains text\n"
        "  --all-domains           also print the full list of every domain seen\n"
        "  --json <file>           write per-flow results as JSON\n", prog);
}

static void classify(Flow& f, const ParsedPacket& p) {
    if (f.domain.empty() && p.payload_len > 0) {
        if (p.is_tcp) {
            if (auto sni = extractSNI(p.payload, p.payload_len)) {
                f.domain = *sni;
                f.app = sniToApp(*sni);
                if (f.app == AppType::UNKNOWN) f.app = AppType::HTTPS;
            } else if (auto host = extractHttpHost(p.payload, p.payload_len)) {
                f.domain = *host;
                f.app = sniToApp(*host);
                if (f.app == AppType::UNKNOWN) f.app = AppType::HTTP;
            }
        } else if (p.is_udp && (p.tuple.src_port == 53 || p.tuple.dst_port == 53)) {
            if (auto q = extractDnsQuery(p.payload, p.payload_len)) {
                f.domain = *q;
                f.app = AppType::DNS;
            }
        }
    }
    if (f.app == AppType::UNKNOWN) {
        uint16_t a = p.tuple.src_port, b = p.tuple.dst_port;
        if (a == 443 || b == 443) f.app = AppType::HTTPS;
        else if (a == 80 || b == 80) f.app = AppType::HTTP;
        else if (a == 53 || b == 53) f.app = AppType::DNS;
    }
}

// Everything the engine remembers. The flow table is shared by all files, so a connection that
// starts in one capture file and continues in the next one is still tracked as ONE flow.
struct Engine {
    Rules rules;
    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows;
    uint64_t total = 0, total_bytes = 0, tcp = 0, udp = 0, other = 0, forwarded = 0, dropped = 0;
    double secs = 0;
    int files = 0;
    bool all_domains = false;

    bool processFile(const std::string& in, const std::string& out) {
        PcapReader reader;
        if (!reader.open(in)) {
            std::fprintf(stderr, "[skip] %s: %s\n", in.c_str(), reader.error().c_str());
            return false;
        }
        PcapWriter writer;
        bool write_out = !out.empty();
        if (write_out && !writer.open(out, reader.header())) {
            std::fprintf(stderr, "[skip] cannot create %s\n", out.c_str());
            return false;
        }
        uint64_t total0 = total, dropped0 = dropped;
        auto t0 = std::chrono::steady_clock::now();
        RawPacket raw;
        while (reader.next(raw)) {
            ++total;
            total_bytes += raw.data.size();
            ParsedPacket p;
            if (!parsePacket(raw.data.data(), raw.data.size(), p)) {
                ++other; ++forwarded;
                if (write_out) writer.write(raw);
                continue;
            }
            (p.is_tcp ? tcp : udp)++;
            FiveTuple key = p.tuple.canonical();
            Flow& f = flows[key];
            f.key = key;
            f.packets++;
            f.bytes += raw.data.size();
            classify(f, p);
            if (!f.blocked && rules.matches(f)) f.blocked = true;
            if (f.blocked) ++dropped;
            else { ++forwarded; if (write_out) writer.write(raw); }
        }
        secs += std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        ++files;
        std::printf("[file] %-40s %6llu packets, %6llu dropped\n", fs::path(in).filename().string().c_str(),
                    (ull)(total - total0), (ull)(dropped - dropped0));
        std::fflush(stdout);
        return true;
    }

    // Groups every named flow into: likely-visited sites, ads/trackers, background, assets, unrecognised.
    void printSiteSummary() const {
        struct Agg { std::set<std::string> domains; uint64_t flows = 0, lookups = 0, bytes = 0; };
        constexpr int NC = static_cast<int>(Category::COUNT);
        std::map<std::string, Agg> byName[NC];
        Agg cat[NC];
        uint64_t named_bytes = 0, dns_bytes = 0;
        for (auto& [k, f] : flows) {
            if (f.domain.empty()) continue;
            SiteInfo si = lookupSite(f.domain);
            int c = static_cast<int>(si.cat);
            std::string name = si.matched ? si.name : f.domain;
            bool dns = f.app == AppType::DNS;
            for (Agg* a : {&byName[c][name], &cat[c]}) {
                a->domains.insert(f.domain);
                if (dns) a->lookups++; else { a->flows++; a->bytes += f.bytes; }
            }
            (dns ? dns_bytes : named_bytes) += f.bytes;
        }
        auto pct = [&](uint64_t b) { return total_bytes ? 100.0 * b / total_bytes : 0.0; };
        auto sorted = [&](int c) {
            std::vector<std::pair<std::string, const Agg*>> rows;
            for (auto& [n, a] : byName[c]) rows.push_back({n, &a});
            std::sort(rows.begin(), rows.end(), [](auto& x, auto& y) {
                return x.second->bytes != y.second->bytes ? x.second->bytes > y.second->bytes
                                                          : x.second->lookups > y.second->lookups; });
            return rows;
        };

        std::printf("\n--- Sites & apps (likely visited, grouped) ---\n");
        std::printf("%-24s %7s %6s %6s %12s %6s\n", "Site", "Domains", "Conns", "DNS", "Bytes", "Share");
        auto sites = sorted(static_cast<int>(Category::SITE));
        for (auto& [n, a] : sites)
            std::printf("%-24s %7zu %6llu %6llu %12llu %5.1f%%\n", n.c_str(), a->domains.size(), (ull)a->flows,
                        (ull)a->lookups, (ull)a->bytes, pct(a->bytes));
        if (sites.empty()) std::printf("(none recognised)\n");

        std::printf("\n--- Everything else ---\n");
        for (Category c : {Category::ADS_TRACKING, Category::BACKGROUND, Category::ASSETS, Category::OTHER}) {
            const Agg& a = cat[static_cast<int>(c)];
            std::printf("%-22s %4zu domains %7llu conns %12llu bytes %5.1f%%\n", categoryName(c), a.domains.size(),
                        (ull)a.flows, (ull)a.bytes, pct(a.bytes));
        }
        std::printf("%-22s %4s         %7s       %12llu bytes %5.1f%%\n", "DNS lookups", "", "", (ull)dns_bytes, pct(dns_bytes));
        uint64_t no_domain = total_bytes - std::min(total_bytes, named_bytes + dns_bytes);
        std::printf("%-22s %4s         %7s       %12llu bytes %5.1f%%   <- no name visible (QUIC, ECH, ...)\n",
                    "No domain visible", "", "", (ull)no_domain, pct(no_domain));

        auto ads = sorted(static_cast<int>(Category::ADS_TRACKING));
        if (!ads.empty()) {
            std::printf("\nTop ad/tracker providers:\n");
            for (size_t n = 0; n < std::min<size_t>(5, ads.size()); ++n)
                std::printf("  %-32s %5llu conns %10llu bytes\n", ads[n].first.c_str(), (ull)ads[n].second->flows,
                            (ull)ads[n].second->bytes);
        }
        auto other = sorted(static_cast<int>(Category::OTHER));
        if (!other.empty()) {
            std::printf("\nUnrecognised domains (add them to src/sites.cpp to teach the engine):\n");
            for (size_t n = 0; n < std::min<size_t>(8, other.size()); ++n)
                std::printf("  %-44s %10llu bytes\n", other[n].first.c_str(), (ull)other[n].second->bytes);
        }
    }

    void report() const {
        constexpr int N = static_cast<int>(AppType::COUNT);
        uint64_t app_pkts[N] = {}, app_bytes[N] = {};
        bool app_blocked[N] = {};
        std::map<std::string, AppType> domains;
        for (auto& [k, f] : flows) {
            int a = static_cast<int>(f.app);
            app_pkts[a] += f.packets; app_bytes[a] += f.bytes;
            if (f.blocked) app_blocked[a] = true;
            if (!f.domain.empty()) domains[f.domain] = f.app == AppType::DNS ? sniToApp(f.domain) : f.app;
        }
        std::printf("\n==================== DPI REPORT ====================\n");
        std::printf("Files: %d   Packets: %llu   Bytes: %llu   Flows: %zu\n", files, (ull)total, (ull)total_bytes, flows.size());
        std::printf("TCP: %llu   UDP: %llu   Other (passed through): %llu\n", (ull)tcp, (ull)udp, (ull)other);
        std::printf("Forwarded: %llu   Dropped: %llu\n", (ull)forwarded, (ull)dropped);
        std::printf("Speed: %.0f packets/sec (%.4f s)\n", secs > 0 ? total / secs : 0.0, secs);

        std::printf("\n--- Application breakdown (by packets) ---\n");
        std::vector<int> order;
        for (int a = 0; a < N; ++a) if (app_pkts[a]) order.push_back(a);
        std::sort(order.begin(), order.end(), [&](int x, int y) { return app_pkts[x] > app_pkts[y]; });
        for (int a : order) {
            double pct = total ? 100.0 * app_pkts[a] / total : 0;
            std::printf("%-10s %6llu pkts %6.1f%%  %8llu bytes  %s ", appName(static_cast<AppType>(a)), (ull)app_pkts[a],
                        pct, (ull)app_bytes[a], std::string(static_cast<size_t>(pct / 2.5), '#').c_str());
            if (app_blocked[a]) std::printf("(BLOCKED)");
            std::printf("\n");
        }
        printSiteSummary();
        if (all_domains) {
            std::printf("\n--- All detected domains (%zu) ---\n", domains.size());
            for (auto& [d, a] : domains) std::printf("  %-40s -> %s\n", d.c_str(), appName(a));
        }

        std::vector<const Flow*> top;
        for (auto& [k, f] : flows) top.push_back(&f);
        std::sort(top.begin(), top.end(), [](const Flow* a, const Flow* b) { return a->bytes > b->bytes; });
        std::printf("\n--- Top flows by bytes ---\n");
        for (size_t n = 0; n < std::min<size_t>(5, top.size()); ++n) {
            const Flow& f = *top[n];
            std::printf("  %s <-> %s  %s  %llu bytes  %s\n", endpointToString(f.key.src_ip, f.key.src_port).c_str(),
                        endpointToString(f.key.dst_ip, f.key.dst_port).c_str(), f.key.proto == 6 ? "TCP" : "UDP",
                        (ull)f.bytes, f.blocked ? "BLOCKED" : "");
        }
    }

    void writeJson(const std::string& path) const {
        std::ofstream js(path);
        js << "{\n  \"files\": " << files << ",\n  \"packets\": " << total << ",\n  \"forwarded\": " << forwarded
           << ",\n  \"dropped\": " << dropped << ",\n  \"flows\": [\n";
        bool first = true;
        for (auto& [k, f] : flows) {
            js << (first ? "" : ",\n") << "    {\"a\": \"" << endpointToString(f.key.src_ip, f.key.src_port)
               << "\", \"b\": \"" << endpointToString(f.key.dst_ip, f.key.dst_port) << "\", \"proto\": \""
               << (f.key.proto == 6 ? "TCP" : "UDP") << "\", \"app\": \"" << appName(f.app) << "\", \"domain\": \""
               << f.domain << "\", \"site\": \"" << (f.domain.empty() ? std::string() : lookupSite(f.domain).matched ? lookupSite(f.domain).name : f.domain)
               << "\", \"category\": \"" << (f.domain.empty() ? "No domain" : categoryName(lookupSite(f.domain).cat))
               << "\", \"packets\": " << f.packets << ", \"bytes\": " << f.bytes
               << ", \"blocked\": " << (f.blocked ? "true" : "false") << "}";
            first = false;
        }
        js << "\n  ]\n}\n";
        std::printf("\nJSON written to %s\n", path.c_str());
    }
};

static bool isPcap(const fs::path& p) { return p.extension() == ".pcap"; }

int main(int argc, char** argv) {
    std::vector<std::string> inputs;
    std::string out_file, out_dir, json_path, watch_dir;
    Engine eng;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&]() -> std::string {
            if (i + 1 >= argc) { std::fprintf(stderr, "missing value for %s\n", a.c_str()); std::exit(1); }
            return argv[++i];
        };
        if (a == "--block-app") {
            AppType t; std::string v = need();
            if (!appFromName(v, t)) { std::fprintf(stderr, "unknown app: %s\n", v.c_str()); return 1; }
            eng.rules.apps.insert(t);
            std::printf("[Rules] Blocked app: %s\n", appName(t));
        } else if (a == "--block-ip") {
            IpAddr ip; std::string v = need();
            if (!ipFromString(v, ip)) { std::fprintf(stderr, "bad ip: %s\n", v.c_str()); return 1; }
            eng.rules.ips.insert(ip);
            std::printf("[Rules] Blocked IP: %s\n", v.c_str());
        } else if (a == "--block-domain") {
            std::string v = toLower(need());
            eng.rules.domains.push_back(v);
            std::printf("[Rules] Blocked domain: %s\n", v.c_str());
        } else if (a == "--json") json_path = need();
        else if (a == "--all-domains") eng.all_domains = true;
        else if (a == "--out") out_file = need();
        else if (a == "--out-dir") out_dir = need();
        else if (a == "--watch") watch_dir = need();
        else if (a.rfind("--", 0) == 0) { usage(argv[0]); return 1; }
        else inputs.push_back(a);
    }
    if (inputs.empty() && watch_dir.empty()) { usage(argv[0]); return 1; }

    // Expand folders into their .pcap files (sorted by name = capture order)
    std::vector<std::string> files;
    for (auto& in : inputs) {
        std::error_code ec;
        if (fs::is_directory(in, ec)) {
            std::vector<std::string> found;
            for (auto& e : fs::directory_iterator(in, ec))
                if (e.is_regular_file() && isPcap(e.path())) found.push_back(e.path().string());
            std::sort(found.begin(), found.end());
            files.insert(files.end(), found.begin(), found.end());
        } else files.push_back(in);
    }
    if (!out_file.empty() && files.size() != 1) {
        std::fprintf(stderr, "--out needs exactly one input file; use --out-dir for many\n"); return 1;
    }
    if (!out_dir.empty()) fs::create_directories(out_dir);
    auto outPathFor = [&](const std::string& in) -> std::string {
        if (!out_file.empty()) return out_file;
        if (!out_dir.empty()) return (fs::path(out_dir) / (fs::path(in).stem().string() + ".filtered.pcap")).string();
        return "";
    };

    for (auto& f : files) eng.processFile(f, outPathFor(f));

    if (!watch_dir.empty()) {
        std::signal(SIGINT, onSigint);
        std::printf("[watch] watching %s  (Ctrl+C to stop and print the report)\n", watch_dir.c_str());
        std::set<std::string> done;
        std::map<std::string, std::uintmax_t> last_size;
        while (!g_stop) {
            std::error_code ec;
            for (auto& e : fs::directory_iterator(watch_dir, ec)) {
                if (!e.is_regular_file() || !isPcap(e.path())) continue;
                std::string p = e.path().string();
                if (done.count(p)) continue;
                std::uintmax_t size = e.file_size(ec);
                auto it = last_size.find(p);
                if (it != last_size.end() && it->second == size && size >= 24) {   // size stopped growing = file finished
                    eng.processFile(p, outPathFor(p));
                    done.insert(p);                                                // never retry (also skips bad files)
                } else last_size[p] = size;
            }
            for (int k = 0; k < 10 && !g_stop; ++k) std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        std::printf("\n[watch] stopped.\n");
    }

    eng.report();
    if (!json_path.empty()) eng.writeJson(json_path);
    return 0;
}

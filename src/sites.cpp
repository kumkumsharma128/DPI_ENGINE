#include "sites.h"
#include "types.h"

namespace {
struct Entry { const char* suffix; const char* name; Category cat; };
constexpr Category S = Category::SITE, A = Category::ADS_TRACKING, B = Category::BACKGROUND, F = Category::ASSETS;

// To teach the engine a new domain, add ONE line here (lower-case suffix, display name, category).
// The categories are a best guess from the domain names; they are not verified for every domain.
const Entry kTable[] = {
    // ---- Sites and apps a person actually opens ----
    {"linkedin.com", "LinkedIn", S},        {"licdn.com", "LinkedIn", S},
    {"instagram.com", "Instagram", S},      {"cdninstagram.com", "Instagram", S},
    {"facebook.com", "Facebook", S},        {"fbcdn.net", "Facebook", S},
    {"youtube.com", "YouTube", S},          {"ytimg.com", "YouTube", S},
    {"googlevideo.com", "YouTube", S},      {"youtu.be", "YouTube", S},
    {"mail.google.com", "Gmail", S},        {"docs.google.com", "Google Docs", S},
    {"drive.google.com", "Google Drive", S},
    {"google.com", "Google", S},            {"google.co.in", "Google", S},
    {"geeksforgeeks.org", "GeeksforGeeks", S},
    {"myntra.com", "Myntra", S},
    {"developer.mozilla.org", "MDN Web Docs", S},
    {"quora.com", "Quora", S},
    {"twitter.com", "Twitter / X", S},      {"x.com", "Twitter / X", S},      {"twimg.com", "Twitter / X", S},
    {"snapchat.com", "Snapchat", S},
    {"github.com", "GitHub", S},            {"githubusercontent.com", "GitHub", S},
    {"netflix.com", "Netflix", S},          {"nflxvideo.net", "Netflix", S},
    {"tiktok.com", "TikTok", S},
    {"amazon.com", "Amazon", S},            {"amazon.in", "Amazon", S},
    {"spotify.com", "Spotify", S},          {"scdn.co", "Spotify", S},
    {"claude.ai", "Claude", S},             {"anthropic.com", "Claude", S},
    {"wikipedia.org", "Wikipedia", S},      {"reddit.com", "Reddit", S},
    {"stackoverflow.com", "Stack Overflow", S},
    {"bing.com", "Bing", S},

    // ---- Advertising, analytics and tracking (more specific than the site entries above, so they win) ----
    {"doubleclick.net", "Google Ads (DoubleClick)", A},
    {"googleadservices.com", "Google Ads", A},   {"googlesyndication.com", "Google Ads", A},
    {"mail-ads.google.com", "Google Ads", A},    {"adservice.google.com", "Google Ads", A},
    {"googletagmanager.com", "Google Analytics / Tag Manager", A},
    {"google-analytics.com", "Google Analytics / Tag Manager", A},
    {"analytics.google.com", "Google Analytics / Tag Manager", A},
    {"clarity.ms", "Microsoft Clarity", A},      {"c.bing.com", "Microsoft Ads (Bing)", A},
    {"adnxs.com", "Xandr (AppNexus)", A},        {"rubiconproject.com", "Magnite (Rubicon)", A},
    {"3lift.com", "TripleLift", A},              {"teads.tv", "Teads", A},
    {"contentsquare.net", "Contentsquare", A},
    {"newrelic.com", "New Relic", A},            {"nr-data.net", "New Relic", A},
    {"go-mpulse.net", "Akamai mPulse", A},
    {"ads-twitter.com", "Twitter Ads", A},       {"analytics.twitter.com", "Twitter Analytics", A},
    {"connect.facebook.net", "Meta Pixel / SDK", A},
    {"tr.snapchat.com", "Snap Pixel", A},        {"tr6.snapchat.com", "Snap Pixel", A},
    {"sc-static.net", "Snap Pixel", A},
    {"a.quora.com", "Quora Pixel", A},
    {"px.ads.linkedin.com", "LinkedIn Ads", A},  {"perf.linkedin.com", "LinkedIn Analytics", A},
    {"trkn.us", "Tracker (trkn.us)", A},

    // ---- Browser / operating system housekeeping ----
    {"safebrowsing.google.com", "Browser safe browsing", B},
    {"safebrowsing.googleapis.com", "Browser safe browsing", B},
    {"gvt1.com", "Chrome updates", B},           {"gvt2.com", "Chrome updates", B},
    {"pki.goog", "Certificate checks", B},
    {"optimizationguide-pa.googleapis.com", "Chrome background", B},
    {"content-autofill.googleapis.com", "Chrome background", B},
    {"update.googleapis.com", "Chrome background", B},
    {"clients2.google.com", "Chrome background", B},  {"clients4.google.com", "Chrome background", B},
    {"googlezip.net", "Chrome background", B},
    {"telemetry.mozilla.org", "Firefox background", B},
    {"microsoft.com", "Microsoft / Windows", B}, {"office.com", "Microsoft / Windows", B},
    {"windowsupdate.com", "Microsoft / Windows", B}, {"msftconnecttest.com", "Microsoft / Windows", B},
    {"live.com", "Microsoft / Windows", B},

    // ---- Shared assets: fonts and CDNs used by many sites ----
    {"fonts.googleapis.com", "Fonts", F},        {"fonts.gstatic.com", "Fonts", F},
    {"typekit.net", "Fonts (Adobe)", F},
    {"gstatic.com", "Google static content", F}, {"googleapis.com", "Google APIs", F},
    {"googleusercontent.com", "Google images / CDN", F}, {"lh3.google.com", "Google images / CDN", F},
};

bool endsWithLabel(const std::string& d, const std::string& suffix) {
    if (d == suffix) return true;
    return d.size() > suffix.size() && d.compare(d.size() - suffix.size(), suffix.size(), suffix) == 0 &&
           d[d.size() - suffix.size() - 1] == '.';
}
}  // namespace

SiteInfo lookupSite(const std::string& domain_in) {
    std::string d = toLower(domain_in);
    while (!d.empty() && d.back() == '.') d.pop_back();
    SiteInfo best;
    size_t best_len = 0;
    for (const Entry& e : kTable) {
        size_t n = std::string(e.suffix).size();
        if (n > best_len && endsWithLabel(d, e.suffix)) {
            best = SiteInfo{e.name, e.cat, true};
            best_len = n;
        }
    }
    return best;
}

const char* categoryName(Category c) {
    switch (c) {
        case Category::SITE: return "Sites & apps";
        case Category::ADS_TRACKING: return "Ads & trackers";
        case Category::BACKGROUND: return "Background / system";
        case Category::ASSETS: return "Assets (fonts, CDN)";
        default: return "Unrecognised";
    }
}

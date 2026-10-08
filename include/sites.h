#pragma once
#include <string>

// Every domain the engine sees is put into one category, and (when known) a site / provider name.
enum class Category { SITE = 0, ADS_TRACKING, BACKGROUND, ASSETS, OTHER, COUNT };

struct SiteInfo {
    std::string name;                 // e.g. "LinkedIn", "Google Ads (DoubleClick)"
    Category cat = Category::OTHER;
    bool matched = false;             // false = domain is not in the table
};

// Matches by domain SUFFIX on label boundaries ("media.licdn.com" matches "licdn.com", "box.com" does not
// match "x.com"). If several entries match, the longest suffix wins ("px.ads.linkedin.com" beats "linkedin.com").
SiteInfo lookupSite(const std::string& domain);
const char* categoryName(Category c);

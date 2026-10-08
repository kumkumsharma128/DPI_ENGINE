#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

// All three are bounds-checked: malformed or truncated input returns nullopt, never crashes.
std::optional<std::string> extractSNI(const uint8_t* payload, size_t len);       // TLS ClientHello
std::optional<std::string> extractHttpHost(const uint8_t* payload, size_t len);  // HTTP "Host:" header
std::optional<std::string> extractDnsQuery(const uint8_t* payload, size_t len);  // DNS question name

<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# SSRF Allow-List Bypass Companion Changelog

## [Unreleased]

## [0.1.0]

### Added

- Hand-written URL/URI parser (this catalog's sixth full grammar)
  combined with a real validate-then-use control-flow check: flags an
  outbound HTTP call (`new URL(...)`, `RestTemplate.getForObject/
  postForObject/exchange/getForEntity`) using an endpoint parameter
  that was only validated with `.startsWith`/`.contains` against a raw
  URL string -- structurally bypassable (CWE-918, confirmed real via
  CVE-2024-22243), not a real host allow-list.

[Unreleased]: https://github.com/GapHunterLabs/ssrf-allowlist-bypass-companion/compare/0.1.0...HEAD
[0.1.0]: https://github.com/GapHunterLabs/ssrf-allowlist-bypass-companion/commits/0.1.0

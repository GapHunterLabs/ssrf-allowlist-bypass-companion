<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# SSRF Allow-List Bypass Companion Changelog

## [Unreleased]

### Added

- A description page for the inspection in **Settings | Editor |
  Inspections**, which showed "Under construction".

### Changed

- The rating prompt's local counter keeps one-way fingerprints of findings
  instead of their file paths, and deletes the list that earlier versions
  kept.
- `PRIVACY.md` describes the values the plugin keeps in the IDE's local
  settings.

## [0.1.1]

### Fixed

- Review/star CTA now links to this plugin's own Marketplace
  reviews page instead of the vendor's generic plugin list.

## [0.1.0]

### Added

- Hand-written URL/URI parser (this catalog's sixth full grammar)
  combined with a real validate-then-use control-flow check: flags an
  outbound HTTP call (`new URL(...)`, `RestTemplate.getForObject/
  postForObject/exchange/getForEntity`) using an endpoint parameter
  that was only validated with `.startsWith`/`.contains` against a raw
  URL string -- structurally bypassable (CWE-918, confirmed real via
  CVE-2024-22243), not a real host allow-list.

[Unreleased]: https://github.com/GapHunterLabs/ssrf-allowlist-bypass-companion/compare/0.1.1...HEAD
[0.1.1]: https://github.com/GapHunterLabs/ssrf-allowlist-bypass-companion/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/GapHunterLabs/ssrf-allowlist-bypass-companion/commits/0.1.0

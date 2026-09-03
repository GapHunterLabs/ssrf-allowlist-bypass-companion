# SSRF Allow-List Bypass Companion

Flags an outbound HTTP call using an endpoint parameter that was only
validated with `.startsWith`/`.contains` against a raw URL string.

## Why it exists

CWE-918 (SSRF). Treating a URL as a plain string and checking whether
an allowed host is a substring/prefix of it is a well-documented,
structurally unsound validation pattern -- confirmed real and current
via **CVE-2024-22243** (Spring Framework, 2024): a regex mismatch in
`UriComponentsBuilder` parsed the userinfo segment differently from
the JDK's own URL handling, so `https://evil.com[@127.0.0.1` passed a
`startsWith`/`getHost()`-style check while the request's real host
differed. This isn't a theoretical weakness -- it's a dated, named CVE
in the exact framework this plugin's sinks target.

## Why built this way

- **Not plain taint-to-sink** -- unlike this catalog's SpEL/XPath/
  LDAP/Lucene sink finders, taint alone reaching an HTTP call is NOT
  what's flagged here (CodeQL's generic Java SSRF query already covers
  that broader shape). This plugin requires the specific
  validate-then-use CONTROL-FLOW pattern: the SAME tainted parameter
  checked with `.startsWith`/`.contains` in an `if` condition, then
  used unchanged in the `then` branch's outbound call -- narrower and
  more precise, and confirmed to not overlap a named competitor for
  this exact angle.
- **A real, hand-written URL/URI parser** -- this catalog's SIXTH full
  grammar (after regex, SpEL, XPath, LDAP, Lucene), and the first with
  authority syntax (`@` as a structural separator, bracketed IPv6
  literals) instead of a boolean query language. Used to confirm the
  validation literal really parses as URL/host syntax, reducing noise
  on unrelated string comparisons.

## v0.1 scope — stated honestly, not exhaustively

- Only a bare (non-concatenated) tainted `String`-typed endpoint
  parameter.
- Only `.startsWith(LITERAL)`/`.contains(LITERAL)` as the recognized
  validation, where `LITERAL` parses as real URL/host syntax.
- The sink must be textually inside the SAME `if`'s `then` branch.
- Only `new URL(...)` and `RestTemplate.getForObject/postForObject/
  exchange/getForEntity` as recognized sinks (checked by class/method
  NAME text, never resolved against the real classpath).
- Percent-encoding is not decoded by the parser -- it only needs to
  confirm the LITERAL allow-list argument is real URL/host syntax,
  never to resolve an attacker-controlled value.

## Usage

Open a Java file with a Spring MVC/JAX-RS endpoint method that checks
a `String` parameter with `.startsWith(...)`/`.contains(...)` against
a URL-shaped literal, then uses that same parameter in `new URL(...)`
or a `RestTemplate` call inside the same `if` -- the call shows a
warning.

## Enterprise / Team Licensing

Need enterprise features, custom rules, or team licensing? Contact us at
**gaphunterlabs@gmail.com**.

## Development

```
./gradlew test           # unit tests
./gradlew buildPlugin    # generates build/distributions/*.zip
./gradlew verifyPlugin   # checks compatibility against real IDEs
```

## License

Apache-2.0. See `LICENSE`.

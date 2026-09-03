package dev.gaphunter.ssrfallowlistbypasscompanion.url

/**
 * Hand-written, scoped RFC-3986-shaped URL/URI parser -- this
 * catalog's SIXTH full grammar (after regex, SpEL, XPath, LDAP,
 * Lucene), and the first with authority syntax (`@` as a structural
 * separator, bracketed IPv6 literals) rather than a boolean query
 * language.
 *
 * **The userinfo split rule is deliberately the LAST unencoded `@` in
 * the authority component** -- the same rule real URL parsers (the
 * JDK's own `java.net.URI`, browsers) use. This is not an arbitrary
 * choice: **CVE-2024-22243** (Spring Framework, 2024) is a real,
 * documented case where `UriComponentsBuilder`'s own regex disagreed
 * with this standard rule, letting `https://evil.com[@127.0.0.1` pass
 * an allow-list `startsWith`/`getHost()` check while the REAL parsed
 * host differed -- concrete proof that naive string validation and
 * real URL parsing can genuinely disagree, which is this plugin's
 * whole reason to exist (see [dev.gaphunter.ssrfallowlistbypasscompanion.detect.JavaSsrfAllowlistBypassFinder]).
 *
 * **v0.1 scope, stated honestly:** [parse] accepts either a full
 * `scheme://[userinfo@]host[:port][/path][?query][#fragment]` or a
 * bare host literal (no scheme) -- both are realistic allow-list
 * literal shapes (`"https://trusted.com"` and `"trusted.com"`, per
 * real examples in security references). Percent-encoding is not
 * decoded (a raw `%40` is just a host/path character here, not
 * unescaped to `@`) -- this plugin only needs to confirm the LITERAL
 * argument is real URL/host syntax, never to resolve or validate any
 * ATTACKER-controlled value (which is unbounded and out of scope for
 * static parsing by design).
 */
object UrlParser {

    fun parse(text: String): UrlNode? {
        if (text.isEmpty()) return null
        val schemeEnd = text.indexOf("://")
        if (schemeEnd > 0 && isValidScheme(text.substring(0, schemeEnd))) {
            return parseFullUrl(text, schemeEnd)
        }
        return parseBareHost(text)
    }

    private fun isValidScheme(s: String): Boolean =
        s.isNotEmpty() && s[0].isLetter() && s.all { it.isLetterOrDigit() || it in "+.-" }

    private fun parseFullUrl(text: String, schemeEnd: Int): UrlNode? {
        val scheme = text.substring(0, schemeEnd)
        var rest = text.substring(schemeEnd + 3)

        var fragment: String? = null
        val hashIdx = rest.indexOf('#')
        if (hashIdx >= 0) {
            fragment = rest.substring(hashIdx + 1)
            rest = rest.substring(0, hashIdx)
        }

        var query: String? = null
        val qIdx = rest.indexOf('?')
        if (qIdx >= 0) {
            query = rest.substring(qIdx + 1)
            rest = rest.substring(0, qIdx)
        }

        var path: String? = null
        val slashIdx = rest.indexOf('/')
        val authority = if (slashIdx >= 0) {
            path = rest.substring(slashIdx)
            rest.substring(0, slashIdx)
        } else {
            rest
        }
        if (authority.isEmpty()) return null

        var authorityRest = authority
        var userinfo: String? = null
        val atIdx = authority.lastIndexOf('@')
        if (atIdx >= 0) {
            userinfo = authority.substring(0, atIdx)
            authorityRest = authority.substring(atIdx + 1)
        }

        val (host, port) = parseHostPort(authorityRest) ?: return null
        return UrlNode(scheme, userinfo, host, port, path, query, fragment)
    }

    private fun parseHostPort(s: String): Pair<String, String?>? {
        if (s.startsWith("[")) {
            val closeIdx = s.indexOf(']')
            if (closeIdx < 0) return null
            val ipv6 = s.substring(1, closeIdx)
            if (!isValidIpv6(ipv6)) return null
            val after = s.substring(closeIdx + 1)
            val port = when {
                after.isEmpty() -> null
                after.startsWith(":") && after.length > 1 && after.substring(1).all(Char::isDigit) -> after.substring(1)
                else -> return null
            }
            return "[$ipv6]" to port
        }
        val colonIdx = s.lastIndexOf(':')
        if (colonIdx >= 0) {
            val portPart = s.substring(colonIdx + 1)
            if (portPart.isNotEmpty() && portPart.all(Char::isDigit)) {
                val host = s.substring(0, colonIdx)
                return if (isValidHostChars(host)) host to portPart else null
            }
        }
        return if (isValidHostChars(s)) s to null else null
    }

    private fun isValidIpv6(s: String): Boolean = s.isNotEmpty() && s.all { it.isDigit() || it in "abcdefABCDEF:." }

    private fun isValidHostChars(s: String): Boolean = s.isNotEmpty() && s.all { it.isLetterOrDigit() || it in "-." }

    private fun parseBareHost(text: String): UrlNode? =
        if (isValidHostChars(text)) UrlNode(null, null, text, null, null, null, null) else null
}

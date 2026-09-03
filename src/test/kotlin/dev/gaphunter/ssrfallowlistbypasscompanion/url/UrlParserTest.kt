package dev.gaphunter.ssrfallowlistbypasscompanion.url

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class UrlParserTest {

    @Test
    fun `a full URL with scheme, host, and path parses correctly`() {
        val node = UrlParser.parse("https://trusted.com/api/data")
        assertEquals(UrlNode("https", null, "trusted.com", null, "/api/data", null, null), node)
    }

    @Test
    fun `a bare host with no scheme parses correctly`() {
        val node = UrlParser.parse("trusted.com")
        assertEquals(UrlNode(null, null, "trusted.com", null, null, null, null), node)
    }

    @Test
    fun `an IPv6 literal with a port parses correctly`() {
        val node = UrlParser.parse("https://[::1]:8080/path")
        assertEquals(UrlNode("https", null, "[::1]", "8080", "/path", null, null), node)
    }

    @Test
    fun `query and fragment are split correctly`() {
        val node = UrlParser.parse("https://trusted.com/path?q=1#frag")
        assertEquals(UrlNode("https", null, "trusted.com", null, "/path", "q=1", "frag"), node)
    }

    @Test
    fun `the userinfo split uses the LAST at-sign, matching real URL parsers`() {
        // The CVE-2024-22243 shape: a real parser resolves the host as
        // 127-0-0-1, NOT evil-com, because of the last-at-sign rule --
        // exactly the discrepancy that made Spring's own regex unsound.
        val node = UrlParser.parse("https://evil.com[@127.0.0.1")
        assertEquals("evil.com[", node?.userinfo)
        assertEquals("127.0.0.1", node?.host)
    }

    @Test
    fun `a userinfo segment is captured separately from the host`() {
        val node = UrlParser.parse("https://user:pass@trusted.com/path")
        assertEquals("user:pass", node?.userinfo)
        assertEquals("trusted.com", node?.host)
    }

    @Test
    fun `an empty string does not parse`() {
        assertNull(UrlParser.parse(""))
    }

    @Test
    fun `a string with spaces does not parse as a bare host`() {
        assertNull(UrlParser.parse("not a url"))
    }

    @Test
    fun `a scheme with no authority does not parse`() {
        assertNull(UrlParser.parse("https://"))
    }
}

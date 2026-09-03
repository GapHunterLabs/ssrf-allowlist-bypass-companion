package dev.gaphunter.ssrfallowlistbypasscompanion.url

/**
 * A parsed URL/URI (RFC 3986-shaped, scoped subset -- see [UrlParser]).
 * [scheme] is null for a bare-host literal (`"trusted.com"`, no
 * `scheme://` prefix) -- still a valid allow-list literal shape, just
 * missing the scheme component.
 */
data class UrlNode(
    val scheme: String?,
    val userinfo: String?,
    val host: String,
    val port: String?,
    val path: String?,
    val query: String?,
    val fragment: String?,
)

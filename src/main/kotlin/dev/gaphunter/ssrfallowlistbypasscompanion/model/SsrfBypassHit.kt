package dev.gaphunter.ssrfallowlistbypasscompanion.model

import com.intellij.psi.PsiElement

/** A confirmed validate-then-use SSRF gap: [variableName] (an endpoint parameter) is checked with `.startsWith`/`.contains` against a real URL/host-shaped literal, then used unchanged at [anchor] in a recognized outbound HTTP call inside that same `if`'s `then` branch -- the validation is structurally bypassable (CVE-2024-22243), not just theoretically weak. */
data class SsrfBypassHit(val anchor: PsiElement, val variableName: String)

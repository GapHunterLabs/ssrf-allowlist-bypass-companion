package dev.gaphunter.ssrfallowlistbypasscompanion.detect

import com.intellij.psi.JavaRecursiveElementWalkingVisitor
import com.intellij.psi.PsiClassType
import com.intellij.psi.PsiCodeBlock
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiExpression
import com.intellij.psi.PsiFile
import com.intellij.psi.PsiIfStatement
import com.intellij.psi.PsiLiteralExpression
import com.intellij.psi.PsiMethod
import com.intellij.psi.PsiMethodCallExpression
import com.intellij.psi.PsiNewExpression
import com.intellij.psi.PsiReferenceExpression
import com.intellij.psi.PsiStatement
import dev.gaphunter.ssrfallowlistbypasscompanion.model.SsrfBypassHit
import dev.gaphunter.ssrfallowlistbypasscompanion.url.UrlParser

/**
 * The first mechanism in this catalog that is NOT plain taint-to-sink
 * -- it requires a specific CONTROL-FLOW shape: an HTTP endpoint
 * parameter (bare reference, same "most dangerous shape flagged
 * unconditionally" convention as this catalog's other sink finders)
 * checked with `.startsWith(LITERAL)`/`.contains(LITERAL)` -- where
 * `LITERAL` parses as real URL/host syntax via [UrlParser], confirming
 * this really is an allow-list check and not an unrelated string
 * comparison -- inside an `if` whose `then` branch uses that SAME
 * parameter, unchanged, in a recognized outbound HTTP call
 * (`new URL(...)`  / `RestTemplate.getForObject/postForObject/
 * exchange/getForEntity`).
 *
 * **Why this is flagged unconditionally once the shape matches:**
 * `.startsWith`/`.contains` against the RAW (unparsed) URL text is
 * structurally bypassable regardless of the specific allow-listed
 * literal -- confirmed real via CVE-2024-22243 (Spring Framework,
 * 2024): `https://evil.com[@127.0.0.1` passes exactly this kind of
 * check while a real parser resolves a different host. The taint
 * alone is not the vulnerability here (as it is in this catalog's
 * SpEL/XPath/LDAP/Lucene sinks) -- the WEAK VALIDATION PATTERN itself
 * is, which is why this finder requires it explicitly instead of
 * flagging on taint reaching the sink alone (that broader, taint-only
 * shape is already covered by CodeQL's generic Java SSRF query --
 * this plugin is deliberately narrower and more precise).
 *
 * **v0.1 scope, stated honestly:** only a bare (non-concatenated)
 * tainted reference; only `.startsWith`/`.contains` as the recognized
 * validation; the sink must be textually inside the SAME `if`'s
 * `then` branch; only `new URL(...)` and `RestTemplate.getForObject/
 * postForObject/exchange/getForEntity` as recognized sinks (checked
 * by class/method NAME text, never resolved against the real
 * classpath); only `String`-typed endpoint parameters.
 */
object JavaSsrfAllowlistBypassFinder {

    private val VALIDATION_METHOD_NAMES = setOf("startsWith", "contains")
    private val REST_TEMPLATE_SINK_METHOD_NAMES = setOf("getForObject", "postForObject", "exchange", "getForEntity")

    fun findAll(file: PsiFile): List<SsrfBypassHit> {
        val hits = mutableListOf<SsrfBypassHit>()
        file.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitMethod(method: PsiMethod) {
                super.visitMethod(method)
                if (!ControllerEndpointSignals.isEndpointMethod(method)) return
                val body = method.body ?: return
                val taintedNames = method.parameterList.parameters
                    .filter { (it.type as? PsiClassType)?.className == "String" }
                    .map { it.name }
                    .toSet()
                if (taintedNames.isEmpty()) return
                hits += hitsInBody(body, taintedNames)
            }
        })
        return hits
    }

    private fun hitsInBody(body: PsiCodeBlock, taintedNames: Set<String>): List<SsrfBypassHit> {
        val hits = mutableListOf<SsrfBypassHit>()
        body.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitIfStatement(statement: PsiIfStatement) {
                super.visitIfStatement(statement)
                val condition = statement.condition ?: return
                val validatedName = validatedTaintedName(condition, taintedNames) ?: return
                val thenBranch = statement.thenBranch ?: return
                val sinkAnchor = findSinkUsing(thenBranch, validatedName) ?: return
                hits += SsrfBypassHit(sinkAnchor, validatedName)
            }
        })
        return hits
    }

    /** Finds `tainted.startsWith(LITERAL)`/`tainted.contains(LITERAL)` anywhere in [condition] -- `tainted` a bare reference in [taintedNames], `LITERAL` a string that parses as real URL/host syntax. Returns the tainted parameter's name. */
    private fun validatedTaintedName(condition: PsiExpression, taintedNames: Set<String>): String? {
        var found: String? = null
        condition.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitMethodCallExpression(call: PsiMethodCallExpression) {
                if (found != null) return
                super.visitMethodCallExpression(call)
                val methodName = call.methodExpression.referenceName ?: return
                if (methodName !in VALIDATION_METHOD_NAMES) return
                val receiver = call.methodExpression.qualifierExpression as? PsiReferenceExpression ?: return
                if (receiver.qualifierExpression != null) return
                val name = receiver.referenceName ?: return
                if (name !in taintedNames) return
                val argument = call.argumentList.expressions.getOrNull(0) as? PsiLiteralExpression ?: return
                val literalText = argument.value as? String ?: return
                if (UrlParser.parse(literalText) == null) return
                found = name
            }
        })
        return found
    }

    /** Finds `new URL(taintedName)` or `restTemplate.getForObject/postForObject/exchange/getForEntity(taintedName, ...)` anywhere in [thenBranch]. */
    private fun findSinkUsing(thenBranch: PsiStatement, taintedName: String): PsiElement? {
        var anchor: PsiElement? = null
        thenBranch.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitNewExpression(expression: PsiNewExpression) {
                if (anchor != null) return
                super.visitNewExpression(expression)
                if (expression.classReference?.referenceName != "URL") return
                if (!firstArgIsBareReference(expression.argumentList?.expressions, taintedName)) return
                anchor = expression.classReference
            }

            override fun visitMethodCallExpression(call: PsiMethodCallExpression) {
                if (anchor != null) return
                super.visitMethodCallExpression(call)
                val methodName = call.methodExpression.referenceName ?: return
                if (methodName !in REST_TEMPLATE_SINK_METHOD_NAMES) return
                val qualifier = call.methodExpression.qualifierExpression ?: return
                if ((qualifier.type as? PsiClassType)?.className != "RestTemplate") return
                if (!firstArgIsBareReference(call.argumentList.expressions, taintedName)) return
                anchor = call.methodExpression.referenceNameElement ?: call.methodExpression
            }
        })
        return anchor
    }

    private fun firstArgIsBareReference(args: Array<PsiExpression>?, taintedName: String): Boolean {
        val first = args?.getOrNull(0) as? PsiReferenceExpression ?: return false
        if (first.qualifierExpression != null) return false
        return first.referenceName == taintedName
    }
}

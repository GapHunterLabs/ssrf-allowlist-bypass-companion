package dev.gaphunter.ssrfallowlistbypasscompanion.inspection

import com.intellij.codeInspection.InspectionManager
import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.psi.PsiFile
import dev.gaphunter.ssrfallowlistbypasscompanion.detect.JavaSsrfAllowlistBypassFinder
import dev.gaphunter.ssrfallowlistbypasscompanion.model.SsrfBypassHit
import dev.gaphunter.ssrfallowlistbypasscompanion.review.ReviewPrompt

/** Flags an outbound HTTP call using an endpoint parameter that was only validated with `.startsWith`/`.contains` -- see [JavaSsrfAllowlistBypassFinder]. */
class SsrfAllowlistBypassInspection : LocalInspectionTool() {

    companion object {
        const val MAX_FILE_LENGTH = 500_000
    }

    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor>? {
        if (file.text.length > MAX_FILE_LENGTH) return null

        val hits = JavaSsrfAllowlistBypassFinder.findAll(file)
        if (hits.isEmpty()) return null

        val problems = hits.map { hit ->
            manager.createProblemDescriptor(
                hit.anchor,
                messageFor(hit),
                isOnTheFly,
                emptyArray(),
                ProblemHighlightType.GENERIC_ERROR_OR_WARNING,
            )
        }

        val path = file.virtualFile?.path
        if (path != null) {
            for (hit in hits) {
                val lineNumber = file.viewProvider.document?.getLineNumber(hit.anchor.textRange.startOffset) ?: -1
                ReviewPrompt.recordHit(file.project, "$path:$lineNumber:${hit.variableName}")
            }
        }

        return problems.toTypedArray()
    }

    private fun messageFor(hit: SsrfBypassHit): String =
        "'${hit.variableName}' was only validated with startsWith/contains against a raw URL string before this outbound call -- " +
            "that check is structurally bypassable (CWE-918, confirmed real via CVE-2024-22243), not a real host allow-list"
}

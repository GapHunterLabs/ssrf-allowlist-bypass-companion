package dev.gaphunter.ssrfallowlistbypasscompanion.inspection

import com.intellij.testFramework.fixtures.BasePlatformTestCase

class SsrfAllowlistBypassInspectionTest : BasePlatformTestCase() {

    override fun setUp() {
        super.setUp()
        myFixture.enableInspections(SsrfAllowlistBypassInspection::class.java)
    }

    fun `test a URL constructor sink guarded only by startsWith is flagged`() {
        myFixture.configureByText(
            "FetchController1.java",
            """
            import java.net.URL;
            import org.springframework.web.bind.annotation.GetMapping;

            class FetchController1 {
                @GetMapping("/fetch")
                Object run(String url) throws Exception {
                    if (url.startsWith("https://trusted.com")) {
                        return new URL(url).openConnection();
                    }
                    return null;
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("CWE-918") == true })
    }

    fun `test a RestTemplate sink guarded only by contains is flagged`() {
        myFixture.configureByText(
            "FetchController2.java",
            """
            import org.springframework.web.bind.annotation.GetMapping;
            import org.springframework.web.client.RestTemplate;

            class FetchController2 {
                @GetMapping("/fetch")
                Object run(String url, RestTemplate restTemplate) {
                    if (url.contains("trusted.com")) {
                        return restTemplate.getForObject(url, String.class);
                    }
                    return null;
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("CWE-918") == true })
    }

    fun `test a sink with no validation at all is not flagged`() {
        myFixture.configureByText(
            "FetchController3.java",
            """
            import java.net.URL;
            import org.springframework.web.bind.annotation.GetMapping;

            class FetchController3 {
                @GetMapping("/fetch")
                Object run(String url) throws Exception {
                    return new URL(url).openConnection();
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("CWE-918") == true })
    }

    fun `test a validation literal that does not parse as URL syntax is not flagged`() {
        myFixture.configureByText(
            "FetchController4.java",
            """
            import java.net.URL;
            import org.springframework.web.bind.annotation.GetMapping;

            class FetchController4 {
                @GetMapping("/fetch")
                Object run(String url) throws Exception {
                    if (url.startsWith("not a url")) {
                        return new URL(url).openConnection();
                    }
                    return null;
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("CWE-918") == true })
    }

    fun `test a sink using a different variable than the validated one is not flagged`() {
        myFixture.configureByText(
            "FetchController5.java",
            """
            import java.net.URL;
            import org.springframework.web.bind.annotation.GetMapping;

            class FetchController5 {
                @GetMapping("/fetch")
                Object run(String url, String other) throws Exception {
                    if (url.startsWith("https://trusted.com")) {
                        return new URL(other).openConnection();
                    }
                    return null;
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("CWE-918") == true })
    }

    fun `test a non-endpoint method with the same shape is not flagged`() {
        myFixture.configureByText(
            "Helper.java",
            """
            import java.net.URL;

            class Helper {
                Object run(String url) throws Exception {
                    if (url.startsWith("https://trusted.com")) {
                        return new URL(url).openConnection();
                    }
                    return null;
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("CWE-918") == true })
    }
}

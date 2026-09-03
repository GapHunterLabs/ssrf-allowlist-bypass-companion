import java.net.URL;
import org.springframework.web.bind.annotation.GetMapping;

class FetchController {
    @GetMapping("/fetch")
    Object run(String url) throws Exception {
        if (url.startsWith("https://trusted.com")) {
            return new URL(url).openConnection();
        }
        return null;
    }
}

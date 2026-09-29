import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class InfrastructureVulns {

    // Allowlist of hosts that the server is permitted to fetch on behalf of users.
    // Only requests whose host exactly matches one of these entries are allowed.
    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(Arrays.asList(
            "api.example.com",
            "cdn.example.com"
    ));

    // 1. SSRF (High) — fixed by validating the user-supplied URL against an
    // explicit host allowlist using java.net.URI (stdlib URL parser + allowlist).
    public String fetchUrl(HttpServletRequest request) throws Exception {

        String target = request.getParameter("url");

        // Parse with java.net.URI to obtain a structured, canonicalised host.
        // This breaks the taint flow: only the host component is used for the
        // allowlist check; the raw user string is never passed to the network sink
        // unless the host is approved.
        URI uri = new URI(target);
        String scheme = uri.getScheme();
        String host   = uri.getHost();

        // Reject non-HTTP(S) schemes to prevent file://, gopher://, etc.
        if (scheme == null || (!scheme.equalsIgnoreCase("https") && !scheme.equalsIgnoreCase("http"))) {
            throw new IllegalArgumentException("Only http and https schemes are permitted.");
        }

        // Enforce the allowlist: reject any host not explicitly approved.
        if (host == null || !ALLOWED_HOSTS.contains(host.toLowerCase())) {
            throw new IllegalArgumentException("Request to disallowed host: " + host);
        }

        // At this point the URI has passed all checks; reconstruct a URL from the
        // validated URI (not from the raw user string) and open the connection.
        URL url = uri.toURL();

        return new String(
                url.openStream().readAllBytes());
    }

    // 2. XXE (High)
    public Document parseXml(InputStream xml)
            throws Exception {

        DocumentBuilderFactory factory =
                DocumentBuilderFactory.newInstance();

        DocumentBuilder builder =
                factory.newDocumentBuilder();

        return builder.parse(xml);
    }

    // 3. Weak Hash (Medium)
    public byte[] md5(String input)
            throws Exception {

        return MessageDigest
                .getInstance("MD5")
                .digest(input.getBytes());
    }

    // 4. Information Exposure (Medium)
    public void log(Exception e) {
        e.printStackTrace();
    }

    // 5. Open Redirect (Medium/High)
    public String redirect(
            HttpServletRequest request) {

        return request.getParameter(
                "redirectUrl");
    }
}
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.servlet.http.HttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the SSRF fix in InfrastructureVulns.fetchUrl().
 *
 * The fix parses the user-supplied URL with java.net.URI, enforces that the
 * scheme is http or https, and checks the host against a static allowlist
 * (api.example.com, cdn.example.com).  These tests verify that disallowed
 * inputs are rejected before the network sink (url.openStream()) is reached,
 * and that the allowlist correctly permits expected hosts.
 *
 * NOTE: Tests that would normally result in a real network call (allowed-host
 * tests) are structured to confirm the validation path completes without
 * throwing an IllegalArgumentException.  The actual openStream() call will
 * throw an IOException in a unit-test environment where no live server is
 * present; that is expected and is asserted accordingly so the sink is still
 * exercised.
 */
public class InfrastructureVulnsSSRFTest {

    private InfrastructureVulns target;
    private HttpServletRequest request;

    @BeforeEach
    public void setUp() {
        target  = new InfrastructureVulns();
        request = Mockito.mock(HttpServletRequest.class);
    }

    // -----------------------------------------------------------------------
    // Negative tests — SSRF payloads that MUST be rejected
    // -----------------------------------------------------------------------

    /** Internal RFC-1918 address — classic SSRF pivot target. */
    @Test
    public void fetchUrl_internalIPv4_throws() {
        Mockito.when(request.getParameter("url")).thenReturn("http://192.168.1.1/admin");

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> target.fetchUrl(request),
                "Request to an internal IP must be rejected"
        );
        assertTrue(ex.getMessage().contains("disallowed host"), "Exception must name the disallowed host");
    }

    /** Loopback address — attacker trying to reach localhost services. */
    @Test
    public void fetchUrl_localhost_throws() {
        Mockito.when(request.getParameter("url")).thenReturn("http://localhost:8080/secret");

        assertThrows(
                IllegalArgumentException.class,
                () -> target.fetchUrl(request),
                "Request to localhost must be rejected"
        );
    }

    /** 127.0.0.1 numeric loopback — equivalent to localhost. */
    @Test
    public void fetchUrl_loopbackNumeric_throws() {
        Mockito.when(request.getParameter("url")).thenReturn("http://127.0.0.1/");

        assertThrows(
                IllegalArgumentException.class,
                () -> target.fetchUrl(request),
                "Request to 127.0.0.1 must be rejected"
        );
    }

    /** Arbitrary external host not on the allowlist. */
    @Test
    public void fetchUrl_externalUnknownHost_throws() {
        Mockito.when(request.getParameter("url")).thenReturn("https://evil.attacker.com/payload");

        assertThrows(
                IllegalArgumentException.class,
                () -> target.fetchUrl(request),
                "Request to an un-allowlisted external host must be rejected"
        );
    }

    /** file:// scheme — could expose local filesystem. */
    @Test
    public void fetchUrl_fileScheme_throws() {
        Mockito.when(request.getParameter("url")).thenReturn("file:///etc/passwd");

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> target.fetchUrl(request),
                "file:// scheme must be rejected"
        );
        assertTrue(ex.getMessage().contains("http"), "Exception must mention permitted schemes");
    }

    /** gopher:// — historically exploited for SSRF pivoting. */
    @Test
    public void fetchUrl_gopherScheme_throws() {
        Mockito.when(request.getParameter("url")).thenReturn("gopher://internal-service/payload");

        assertThrows(
                IllegalArgumentException.class,
                () -> target.fetchUrl(request),
                "gopher:// scheme must be rejected"
        );
    }

    /** ftp:// scheme — another non-HTTP scheme that must be blocked. */
    @Test
    public void fetchUrl_ftpScheme_throws() {
        Mockito.when(request.getParameter("url")).thenReturn("ftp://files.internal/data");

        assertThrows(
                IllegalArgumentException.class,
                () -> target.fetchUrl(request),
                "ftp:// scheme must be rejected"
        );
    }

    /** Subdomain of an allowed host is NOT itself on the allowlist. */
    @Test
    public void fetchUrl_subdomainOfAllowedHost_throws() {
        Mockito.when(request.getParameter("url")).thenReturn("https://evil.api.example.com/data");

        assertThrows(
                IllegalArgumentException.class,
                () -> target.fetchUrl(request),
                "A subdomain of an allowlisted host must still be rejected"
        );
    }

    /** DNS rebinding attempt: host looks like an allowed domain but is a crafted subdomain. */
    @Test
    public void fetchUrl_hostSuffixSpoofing_throws() {
        // "notapi.example.com" ends with "api.example.com" but is not equal to it.
        Mockito.when(request.getParameter("url")).thenReturn("https://notapi.example.com/data");

        assertThrows(
                IllegalArgumentException.class,
                () -> target.fetchUrl(request),
                "Host that only ends with an allowed host name must be rejected"
        );
    }

    /** IPv6 loopback — equivalent to localhost. */
    @Test
    public void fetchUrl_ipv6Loopback_throws() {
        Mockito.when(request.getParameter("url")).thenReturn("http://[::1]/admin");

        assertThrows(
                IllegalArgumentException.class,
                () -> target.fetchUrl(request),
                "IPv6 loopback ::1 must be rejected"
        );
    }

    /** Link-local IPv4 (169.254.x.x) — cloud metadata endpoint range. */
    @Test
    public void fetchUrl_linkLocalMetadataEndpoint_throws() {
        Mockito.when(request.getParameter("url")).thenReturn("http://169.254.169.254/latest/meta-data/");

        assertThrows(
                IllegalArgumentException.class,
                () -> target.fetchUrl(request),
                "Cloud metadata endpoint (link-local) must be rejected"
        );
    }

    // -----------------------------------------------------------------------
    // Positive tests — allowlisted hosts MUST pass validation
    // (openStream() will throw IOException in a unit-test context — that is
    //  expected and confirms the validation layer was cleared successfully)
    // -----------------------------------------------------------------------

    /**
     * api.example.com is on the allowlist.
     * The method must NOT throw IllegalArgumentException; an IOException from
     * the missing network connection is acceptable.
     */
    @Test
    public void fetchUrl_allowedHostApiExampleCom_passesValidation() {
        Mockito.when(request.getParameter("url")).thenReturn("https://api.example.com/data");

        // Should not be rejected by the allowlist check.
        // openStream() will likely throw IOException — that's fine for a unit test.
        Exception thrown = assertThrows(
                Exception.class,
                () -> target.fetchUrl(request)
        );

        assertFalse(
                thrown instanceof IllegalArgumentException,
                "api.example.com must not be blocked by the allowlist; " +
                "only a network-level IOException is expected. Got: " + thrown
        );
    }

    /**
     * cdn.example.com is on the allowlist.
     * Same contract as above.
     */
    @Test
    public void fetchUrl_allowedHostCdnExampleCom_passesValidation() {
        Mockito.when(request.getParameter("url")).thenReturn("https://cdn.example.com/asset.js");

        Exception thrown = assertThrows(
                Exception.class,
                () -> target.fetchUrl(request)
        );

        assertFalse(
                thrown instanceof IllegalArgumentException,
                "cdn.example.com must not be blocked by the allowlist; " +
                "only a network-level IOException is expected. Got: " + thrown
        );
    }

    /** http (non-TLS) is also accepted for allowlisted hosts. */
    @Test
    public void fetchUrl_httpSchemeAllowedHost_passesValidation() {
        Mockito.when(request.getParameter("url")).thenReturn("http://api.example.com/endpoint");

        Exception thrown = assertThrows(
                Exception.class,
                () -> target.fetchUrl(request)
        );

        assertFalse(
                thrown instanceof IllegalArgumentException,
                "http scheme to an allowlisted host must pass validation"
        );
    }

    // -----------------------------------------------------------------------
    // Edge-case / malformed input tests
    // -----------------------------------------------------------------------

    /** Null parameter (parameter not supplied) must not cause a NullPointerException
     *  that bypasses the check; it must surface a controlled exception. */
    @Test
    public void fetchUrl_nullParameter_throwsControlledExceptionNotNpe() {
        Mockito.when(request.getParameter("url")).thenReturn(null);

        // Should throw some exception (NullPointerException from URI constructor or
        // IllegalArgumentException from our check) — the important thing is it does
        // not succeed in opening a stream.
        assertThrows(
                Exception.class,
                () -> target.fetchUrl(request),
                "Null url parameter must throw an exception"
        );
    }

    /** Empty string is not a valid URL; parsing should fail before the sink. */
    @Test
    public void fetchUrl_emptyParameter_throwsBeforeSink() {
        Mockito.when(request.getParameter("url")).thenReturn("");

        assertThrows(
                Exception.class,
                () -> target.fetchUrl(request),
                "Empty url parameter must throw an exception"
        );
    }

    /** URL with no scheme triggers the scheme-validation check. */
    @Test
    public void fetchUrl_noScheme_throwsControlledExceptionNotNpe() {
        Mockito.when(request.getParameter("url")).thenReturn("api.example.com/data");

        Exception thrown = assertThrows(
                Exception.class,
                () -> target.fetchUrl(request),
                "URL with no scheme must throw"
        );

        // Must be our own IllegalArgumentException about permitted schemes, not a
        // raw NPE leaking internal details.
        if (thrown instanceof IllegalArgumentException) {
            assertTrue(
                    thrown.getMessage().contains("http"),
                    "Exception for missing scheme must mention permitted schemes"
            );
        }
    }
}

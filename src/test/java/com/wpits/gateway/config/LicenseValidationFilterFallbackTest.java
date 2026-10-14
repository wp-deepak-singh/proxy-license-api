package com.wpits.gateway.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netflix.zuul.context.RequestContext;
import com.wpits.gateway.service.KeygenService;
import com.wpits.gateway.service.LicenseFileService;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.math.BigDecimal;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LicenseValidationFilterFallbackTest {

    private static final String LICENSE_KEY = "installation-license-key";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RecordingRestTemplate restTemplate = new RecordingRestTemplate();
    private Path storagePath;
    private Ed25519PrivateKeyParameters privateKey;
    private String publicKeyHex;
    private LicenseValidationFilter filter;

    @BeforeEach
    void setUp() throws Exception {
        RequestContext.testSetCurrentContext(new RequestContext());
        storagePath = Files.createTempDirectory("installation-license").resolve("license.lic");
        Ed25519KeyPairGenerator generator = new Ed25519KeyPairGenerator();
        generator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        privateKey = (Ed25519PrivateKeyParameters) keyPair.getPrivate();
        publicKeyHex = Hex.toHexString(((Ed25519PublicKeyParameters) keyPair.getPublic()).getEncoded());

        installCertificate(LICENSE_KEY, "2099-01-01T00:00:00Z", 72);
        useClock(Clock.systemUTC());
        restTemplate.failure = new ResourceAccessException(
                "I/O error on POST request", new ConnectException("Connection refused"));
    }

    @AfterEach
    void tearDown() throws Exception {
        RequestContext.getCurrentContext().unset();
        if (storagePath != null) {
            Files.deleteIfExists(storagePath);
            Files.deleteIfExists(storagePath.getParent());
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("unreachableKeygen")
    void allowsGatedRequestWhenKeygenIsUnreachable(String reason, RuntimeException failure) {
        restTemplate.failure = failure;
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertCoveringFileAllows(context, reason);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("nonValidKeygenResults")
    void allowsGatedRequestWhenKeygenResultIsNotValid(String reason, String body) {
        restTemplate.failure = null;
        restTemplate.response = ResponseEntity.ok(body);
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertCoveringFileAllows(context, reason);
    }

    @Test
    void allowsGatedRequestWhenKeygenReturnsAnHttpErrorStatus() {
        restTemplate.failure = null;
        restTemplate.response = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("unavailable");
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertCoveringFileAllows(context, "http error status");
    }

    @Test
    void allowsGatedRequestWhenOnlineValidationSucceedsEvenIfInstallationFileDoesNotCover() throws Exception {
        installCertificate(LICENSE_KEY, "2020-06-15T12:30:00Z", null);
        useClock(Clock.fixed(Instant.parse("2020-06-15T12:30:01Z"), ZoneOffset.UTC));
        restTemplate.failure = null;
        restTemplate.response = ResponseEntity.ok(
                "{\"meta\":{\"valid\":true},\"data\":{\"attributes\":{\"status\":\"ACTIVE\"}}}");
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertTrue(context.sendZuulResponse(), "successful online validation does not decide from the file");
    }

    @Test
    void allowsGatedRequestBeforeStoredExpiryWithoutGrace() throws Exception {
        installCertificate(LICENSE_KEY, "2020-06-15T12:30:00Z", null);
        useClock(Clock.fixed(Instant.parse("2020-06-15T12:29:59Z"), ZoneOffset.UTC));
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertTrue(context.sendZuulResponse(), "stored expiry still ahead covers without grace");
        assertEquals(1, restTemplate.calls.size(), "fallback makes no further Keygen call");
    }

    @Test
    void allowsGatedRequestAtGraceDeadlineAfterStoredExpiry() throws Exception {
        installCertificate(LICENSE_KEY, "2026-01-01T00:00:00Z", 5);
        useClock(Clock.fixed(Instant.parse("2026-01-01T05:00:00Z"), ZoneOffset.UTC));
        restTemplate.failure = null;
        restTemplate.response = ResponseEntity.ok(
                "{\"meta\":{\"valid\":true,\"code\":\"EXPIRED\"},\"data\":{\"attributes\":{\"status\":\"EXPIRED\"}}}");
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertTrue(context.sendZuulResponse(), "grace deadline is still inside coverage");
        assertEquals(1, restTemplate.calls.size(), "grace comes from the certificate, not Keygen");
    }

    @Test
    void allowsGatedRequestAtStoredExpiryWithoutGrace() throws Exception {
        installCertificate(LICENSE_KEY, "2020-06-15T12:30:00Z", null);
        useClock(Clock.fixed(Instant.parse("2020-06-15T12:30:00Z"), ZoneOffset.UTC));
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertCoveringFileAllows(context, "expiry instant");
    }

    @Test
    void allowsGatedRequestAtGraceDeadlineForAFractionalHour() throws Exception {
        installCertificate(LICENSE_KEY, "2026-01-01T00:00:00Z", 1.5d);
        useClock(Clock.fixed(Instant.parse("2026-01-01T01:30:00Z"), ZoneOffset.UTC));
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertCoveringFileAllows(context, "fractional grace");
    }

    @Test
    void allowsGatedRequestAtGraceDeadlineForARepeatingFractionalHour() throws Exception {
        installCertificate(LICENSE_KEY, "2026-01-01T00:00:00Z", new BigDecimal("0.6666666666666666"));
        useClock(Clock.fixed(Instant.parse("2026-01-01T00:40:00Z"), ZoneOffset.UTC));
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertCoveringFileAllows(context, "repeating fractional grace");
    }

    @Test
    void deniesGatedRequestOneSecondAfterGraceDeadline() throws Exception {
        installCertificate(LICENSE_KEY, "2026-01-01T00:00:00Z", 5);
        useClock(Clock.fixed(Instant.parse("2026-01-01T05:00:01Z"), ZoneOffset.UTC));
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertFallbackDenied(context);
    }

    @Test
    void deniesGatedRequestAfterStoredExpiryWhenGraceIsMissing() throws Exception {
        installCertificate(LICENSE_KEY, "2020-06-15T12:30:00Z", null);
        useClock(Clock.fixed(Instant.parse("2020-06-15T12:30:01Z"), ZoneOffset.UTC));
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertFallbackDenied(context);
    }

    @Test
    void deniesGatedRequestAfterStoredExpiryWhenGraceIsNotANumber() throws Exception {
        installCertificate(LICENSE_KEY, "2020-06-15T12:30:00Z", "5");
        useClock(Clock.fixed(Instant.parse("2020-06-15T12:30:01Z"), ZoneOffset.UTC));
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertFallbackDenied(context);
    }

    @Test
    void deniesGatedRequestWhenLicenseKeyHeaderIsMissing() {
        restTemplate.failure = null;
        RequestContext context = gatedRequest(null);

        filter.run();

        assertDeniedWithoutKeygen(context);
    }

    @Test
    void deniesGatedRequestWhenLicenseKeyHeaderIsBlank() {
        restTemplate.failure = null;
        RequestContext context = gatedRequest("   ");

        filter.run();

        assertDeniedWithoutKeygen(context);
    }

    @Test
    void deniesGatedRequestWhenInstallationFileIsMissing() throws Exception {
        Files.deleteIfExists(storagePath);
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertFallbackDenied(context);
    }

    @Test
    void deniesGatedRequestWhenInstallationFileIsUnreadable() throws Exception {
        Files.deleteIfExists(storagePath);
        Files.createDirectory(storagePath);
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertFallbackDenied(context);
    }

    @Test
    void deniesGatedRequestWhenInstallationFileSignatureIsInvalid() throws Exception {
        Ed25519KeyPairGenerator generator = new Ed25519KeyPairGenerator();
        generator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        Ed25519PrivateKeyParameters otherKey =
                (Ed25519PrivateKeyParameters) generator.generateKeyPair().getPrivate();
        Files.deleteIfExists(storagePath);
        Files.write(storagePath, certificate(otherKey, LICENSE_KEY, "2099-01-01T00:00:00Z", 72)
                .getBytes(StandardCharsets.UTF_8));
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertFallbackDenied(context);
    }

    @Test
    void deniesGatedRequestWhenInstallationFileHasNoExpiry() throws Exception {
        installCertificate(LICENSE_KEY, null, 72);
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertFallbackDenied(context);
    }

    @Test
    void deniesGatedRequestWhenInstallationFileExpiryIsNotAnInstant() throws Exception {
        installCertificate(LICENSE_KEY, "tomorrow", 72);
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertFallbackDenied(context);
    }

    @Test
    void deniesGatedRequestWhenInstallationFileHasNoKey() throws Exception {
        installCertificate(null, "2099-01-01T00:00:00Z", 72);
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertFallbackDenied(context);
    }

    @Test
    void deniesGatedRequestWhenHeaderKeyDiffersFromInstallationFile() {
        RequestContext context = gatedRequest("other-license-key");

        filter.run();

        assertFallbackDenied(context);
    }

    @Test
    void exemptRoutesStayAllowedWithoutALicenseCheck() throws Exception {
        Files.deleteIfExists(storagePath);
        String[] uris = {"/api/client/auth", "/api/client/auth/login", "/actuator", "/actuator/health"};
        for (String uri : uris) {
            RequestContext context = RequestContext.getCurrentContext();
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setRequestURI(uri);
            context.setRequest(request);
            context.setResponse(new MockHttpServletResponse());

            assertFalse(filter.shouldFilter(), uri);
            assertTrue(context.sendZuulResponse(), uri);
        }
        assertEquals(0, restTemplate.calls.size());
    }

    @Test
    void gatedRouteStillRunsTheLicenseFilter() {
        gatedRequest(LICENSE_KEY);

        assertTrue(filter.shouldFilter());
    }

    private void assertCoveringFileAllows(RequestContext context, String reason) {
        assertTrue(context.sendZuulResponse(), reason);
        assertEquals(1, restTemplate.calls.size(), "fallback makes no further Keygen call");
        assertTrue(restTemplate.calls.get(0).contains("validate-key"), restTemplate.calls.toString());
        assertFalse(restTemplate.calls.get(0).contains("check-out"));
    }

    private void assertFallbackDenied(RequestContext context) {
        assertFalse(context.sendZuulResponse());
        assertEquals(401, context.getResponseStatusCode());
        assertEquals(1, restTemplate.calls.size(), "a denied fallback still does not check out or look up grace");
        assertTrue(restTemplate.calls.get(0).contains("validate-key"));
    }

    private void assertDeniedWithoutKeygen(RequestContext context) {
        assertFalse(context.sendZuulResponse());
        assertEquals(401, context.getResponseStatusCode());
        assertEquals(0, restTemplate.calls.size(), "a missing license key does not open the fallback");
    }

    private static Stream<Arguments> unreachableKeygen() {
        return Stream.of(
                Arguments.of("connection refused",
                        new ResourceAccessException("I/O error", new ConnectException("Connection refused"))),
                Arguments.of("connect timeout",
                        new ResourceAccessException("I/O error", new SocketTimeoutException("connect timed out"))),
                Arguments.of("read timeout",
                        new ResourceAccessException("I/O error", new SocketTimeoutException("Read timed out"))),
                Arguments.of("unknown host",
                        new ResourceAccessException("I/O error", new UnknownHostException("keygen.test"))),
                Arguments.of("http error", new HttpServerErrorException(HttpStatus.BAD_GATEWAY)),
                Arguments.of("http client error", new HttpClientErrorException(HttpStatus.UNAUTHORIZED)));
    }

    private static Stream<Arguments> nonValidKeygenResults() {
        return Stream.of(
                Arguments.of("fingerprint mismatch", validationBody(false, "FINGERPRINT_SCOPE_MISMATCH", "ACTIVE")),
                Arguments.of("expired", validationBody(true, "EXPIRED", "EXPIRED")),
                Arguments.of("suspended", validationBody(true, "SUSPENDED", "SUSPENDED")),
                Arguments.of("banned", validationBody(true, "BANNED", "BANNED")),
                Arguments.of("not valid", validationBody(false, "NOT_FOUND", "ACTIVE")));
    }

    private static String validationBody(boolean valid, String code, String status) {
        return "{\"meta\":{\"valid\":" + valid + ",\"code\":\"" + code + "\"},\"data\":{\"attributes\":{\"status\":\""
                + status + "\"}}}";
    }

    @Test
    void deniesGatedRequestWhenLicenseFileExpiryIsMissing() throws Exception {
        installCertificate(LICENSE_KEY, "2099-01-01T00:00:00Z", 72, null);
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertFallbackDenied(context);
    }

    @Test
    void deniesGatedRequestWhenLicenseFileExpiryIsNotAnInstant() throws Exception {
        installCertificate(LICENSE_KEY, "2099-01-01T00:00:00Z", 72, "not-an-instant");
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertFallbackDenied(context);
    }

    @Test
    void deniesGatedRequestWhenLicenseFileHasExpiredEvenIfInnerLicenseIsStillValid() throws Exception {
        installCertificate(LICENSE_KEY, "2099-01-01T00:00:00Z", null, "2026-06-01T12:00:00Z");
        useClock(Clock.fixed(Instant.parse("2026-06-01T12:00:01Z"), ZoneOffset.UTC));
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertFallbackDenied(context);
    }

    @Test
    void deniesGatedRequestWhenLicenseFileHasExpiredEvenIfInnerLicenseIsInsideGrace() throws Exception {
        installCertificate(LICENSE_KEY, "2026-01-01T00:00:00Z", 72, "2026-01-02T00:00:00Z");
        useClock(Clock.fixed(Instant.parse("2026-01-02T00:00:01Z"), ZoneOffset.UTC));
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertFallbackDenied(context);
    }

    @Test
    void allowsGatedRequestWhenLicenseFileExpiryInstantHasNotPassed() throws Exception {
        installCertificate(LICENSE_KEY, "2099-01-01T00:00:00Z", null, "2026-06-01T12:00:00Z");
        useClock(Clock.fixed(Instant.parse("2026-06-01T11:59:59Z"), ZoneOffset.UTC));
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertCoveringFileAllows(context, "before file expiry");
    }

    @Test
    void allowsGatedRequestAtExactLicenseFileExpiryInstant() throws Exception {
        installCertificate(LICENSE_KEY, "2099-01-01T00:00:00Z", null, "2026-06-01T12:00:00Z");
        useClock(Clock.fixed(Instant.parse("2026-06-01T12:00:00Z"), ZoneOffset.UTC));
        RequestContext context = gatedRequest(LICENSE_KEY);

        filter.run();

        assertCoveringFileAllows(context, "exact file expiry instant");
    }

    @Test
    void exemptRoutesStayAllowedWhenLicenseFileHasExpired() throws Exception {
        installCertificate(LICENSE_KEY, "2099-01-01T00:00:00Z", null, "2020-01-01T00:00:00Z");
        useClock(Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));

        String[] uris = {"/api/client/auth", "/api/client/auth/login", "/actuator", "/actuator/health"};
        for (String uri : uris) {
            RequestContext context = RequestContext.getCurrentContext();
            MockHttpServletRequest request = new MockHttpServletRequest();
            request.setRequestURI(uri);
            context.setRequest(request);
            context.setResponse(new MockHttpServletResponse());

            assertFalse(filter.shouldFilter(), uri);
            assertTrue(context.sendZuulResponse(), uri);
        }
        assertEquals(0, restTemplate.calls.size());
    }

    private void installCertificate(String licenseKey, String expiry, Object graceHours) throws Exception {
        installCertificate(licenseKey, expiry, graceHours, "2099-01-01T00:00:00Z");
    }

    private void installCertificate(String licenseKey, String expiry, Object graceHours, String fileExpiry) throws Exception {
        Files.deleteIfExists(storagePath);
        Files.write(storagePath, certificate(privateKey, licenseKey, expiry, graceHours, fileExpiry).getBytes(StandardCharsets.UTF_8));
    }

    private void useClock(Clock clock) {
        KeygenService keygenService = new KeygenService(
                objectMapper, "account", "token", "http://keygen.test", restTemplate);
        LicenseFileService licenseFileService = new LicenseFileService(
                restTemplate,
                objectMapper,
                keygenService,
                "product",
                "http://keygen.test",
                "account",
                "token",
                publicKeyHex,
                storagePath.toString(),
                clock);
        filter = new LicenseValidationFilter(restTemplate, objectMapper, licenseFileService);
    }

    private RequestContext gatedRequest(String licenseKey) {
        RequestContext context = RequestContext.getCurrentContext();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/sms/send");
        if (licenseKey != null) {
            request.addHeader("X-License-Key", licenseKey);
        }
        context.setRequest(request);
        context.setResponse(new MockHttpServletResponse());
        return context;
    }

    private String certificate(Ed25519PrivateKeyParameters privateKey, String licenseKey, String expiry, Object graceHours)
            throws Exception {
        return certificate(privateKey, licenseKey, expiry, graceHours, "2099-01-01T00:00:00Z");
    }

    private String certificate(Ed25519PrivateKeyParameters privateKey, String licenseKey, String expiry, Object graceHours, String fileExpiry)
            throws Exception {
        ObjectNode license = objectMapper.createObjectNode();
        ObjectNode attributes = license.putObject("data").putObject("attributes");
        if (licenseKey != null) {
            attributes.put("key", licenseKey);
        }
        if (expiry != null) {
            attributes.put("expiry", expiry);
        }
        if (graceHours instanceof Integer) {
            attributes.putObject("metadata").put("graceExpiryInHours", (Integer) graceHours);
        } else if (graceHours instanceof Double) {
            attributes.putObject("metadata").put("graceExpiryInHours", (Double) graceHours);
        } else if (graceHours instanceof String) {
            attributes.putObject("metadata").put("graceExpiryInHours", (String) graceHours);
        } else if (graceHours instanceof BigDecimal) {
            attributes.putObject("metadata").put("graceExpiryInHours", (BigDecimal) graceHours);
        }
        if (fileExpiry != null) {
            license.putObject("meta").put("expiry", fileExpiry);
        }
        String enc = Base64.getEncoder().encodeToString(
                objectMapper.writeValueAsBytes(license));
        String sig = sign(privateKey, "license/" + enc);
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("enc", enc);
        payload.put("sig", sig);
        String encoded = Base64.getEncoder().encodeToString(objectMapper.writeValueAsBytes(payload));
        return "-----BEGIN LICENSE FILE-----\n" + encoded + "\n-----END LICENSE FILE-----\n";
    }

    private String sign(Ed25519PrivateKeyParameters privateKey, String signedData) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privateKey);
        byte[] bytes = signedData.getBytes(StandardCharsets.UTF_8);
        signer.update(bytes, 0, bytes.length);
        return Base64.getEncoder().encodeToString(signer.generateSignature());
    }

    private static class RecordingRestTemplate extends RestTemplate {
        private final List<String> calls = new ArrayList<String>();
        private RuntimeException failure;
        private ResponseEntity<String> response;

        @Override
        @SuppressWarnings("unchecked")
        public <T> ResponseEntity<T> postForEntity(String url, Object request, Class<T> responseType,
                                                   Object... uriVariables) {
            calls.add(url);
            if (failure != null) {
                throw failure;
            }
            if (response != null) {
                return (ResponseEntity<T>) response;
            }
            throw new IllegalStateException("no Keygen response stubbed");
        }

        @Override
        public <T> ResponseEntity<T> exchange(String url, HttpMethod method, HttpEntity<?> requestEntity,
                                              Class<T> responseType, Object... uriVariables) {
            calls.add(url);
            throw new IllegalStateException("unexpected Keygen call " + url);
        }
    }
}

package com.wpits.gateway.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;

@Service
public class LicenseFileService {

    private static final String BEGIN_LICENSE_FILE = "-----BEGIN LICENSE FILE-----";
    private static final String END_LICENSE_FILE = "-----END LICENSE FILE-----";

    private final ObjectMapper objectMapper;
    private final String publicKeyHex;
    private final String productId;
    private final Path storagePath;
    private final KeygenService keygenService;
    private final Clock clock;

    @Autowired
    public LicenseFileService(
            RestTemplate restTemplate,
            ObjectMapper objectMapper,
            KeygenService keygenService,
            @Value("${keygen.product-id}") String productId,
            @Value("${keygen.api-url}") String keygenApiUrl,
            @Value("${keygen.account-id}") String accountId,
            @Value("${keygen.token}") String token,
            @Value("${keygen.public-key}") String publicKeyHex,
            @Value("${keygen.storage.path:license.lic}") String storagePath) {
        this(restTemplate, objectMapper, keygenService, productId, keygenApiUrl, accountId, token,
                publicKeyHex, storagePath, Clock.systemUTC());
    }

    public LicenseFileService(
            RestTemplate restTemplate,
            ObjectMapper objectMapper,
            KeygenService keygenService,
            String productId,
            String keygenApiUrl,
            String accountId,
            String token,
            String publicKeyHex,
            String storagePath,
            Clock clock) {
        this.objectMapper = objectMapper;
        this.keygenService = keygenService;
        this.publicKeyHex = publicKeyHex;
        this.productId = productId;
        this.storagePath = Paths.get(storagePath);
        this.clock = clock;
    }

    public Path checkOutAndSaveLicenseFile(String licenseId) throws IOException {
        if (productId == null || productId.trim().isEmpty()) {
            throw new IllegalStateException("Missing productId");
        }

        // Checkout the offline license certificate.
        String certificate = keygenService.checkOutLicenseFile(licenseId);

        // Verify before saving.
        LicenseFileValidationResult result = validateLicenseFile(certificate);

        if (!result.isValid()) {
            throw new IllegalStateException(
                    "Invalid license file: " + result.getReason());
        }

        Path absolutePath = storagePath.toAbsolutePath();
        Path parent = absolutePath.getParent();

        if (parent != null) {
            Files.createDirectories(parent);
        }

        Path tempPath = Files.createTempFile(
                parent, "license-", ".tmp");

        try {
            Files.write(
                    tempPath,
                    certificate.getBytes(StandardCharsets.UTF_8));

            try {
                Files.move(
                        tempPath,
                        absolutePath,
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                Files.move(
                        tempPath,
                        absolutePath,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tempPath);
        }

        return absolutePath;
    }

    public boolean covers(String headerLicenseKey) {
        try {
            String certificate = new String(Files.readAllBytes(storagePath), StandardCharsets.UTF_8);
            JsonNode payload = decodePayload(certificate);
            String enc = payload.path("enc").asText();
            String sig = payload.path("sig").asText();
            if (enc.isEmpty() || sig.isEmpty() || !verifyEd25519("license/" + enc, sig)) {
                return false;
            }

            JsonNode attributes = objectMapper
                    .readTree(Base64.getDecoder().decode(enc))
                    .path("data")
                    .path("attributes");
            if (!headerLicenseKey.equals(attributes.path("key").asText(""))) {
                return false;
            }

            String expiry = attributes.path("expiry").asText("");
            if (expiry.trim().isEmpty()) {
                return false;
            }
            Instant expiryTime = Instant.parse(expiry);
            Instant now = clock.instant();
            if (!now.isAfter(expiryTime)) {
                return true;
            }

            JsonNode graceHours = attributes.path("metadata").path("graceExpiryInHours");
            if (!graceHours.isNumber()) {
                return false;
            }
            return !now.isAfter(expiryTime.plus(graceDuration(graceHours)));
        } catch (Exception ex) {
            return false;
        }
    }

    public LicenseFileValidationResult validateSavedLicenseFile() throws IOException {
        return validateLicenseFile(new String(Files.readAllBytes(storagePath), StandardCharsets.UTF_8));
    }

    public LicenseFileValidationResult validateLicenseFile(
        String certificate) throws IOException {

    JsonNode payload = decodePayload(certificate);

    String enc = payload.path("enc").asText();
    String sig = payload.path("sig").asText();

    if (enc.isEmpty() || sig.isEmpty()) {
        return LicenseFileValidationResult.invalid(
                "License file payload must contain enc and sig");
    }

    if (!verifyEd25519("license/" + enc, sig)) {
        return LicenseFileValidationResult.invalid(
                "Invalid license file signature");
    }

    JsonNode decoded = objectMapper.readTree(
            new String(
                    Base64.getDecoder().decode(enc),
                    StandardCharsets.UTF_8));

    // 1. Check the actual license expiry.
    String licenseExpiry = decoded.path("data")
            .path("attributes")
            .path("expiry")
            .asText(null);

    if (licenseExpiry == null || licenseExpiry.trim().isEmpty()) {
        return LicenseFileValidationResult.invalid(
                "License expiry is missing");
    }

    Instant licenseExpiryTime = Instant.parse(licenseExpiry);
    Instant now = Instant.now();

    // License is still valid.
    if (!now.isAfter(licenseExpiryTime)) {
        return LicenseFileValidationResult.valid(
                decoded.path("data"));
    }

    // 2. License expired; apply configured grace period.
    long graceHours =
            keygenService.getOfflineLicenseGraceHours(productId);

    Instant graceDeadline =
            licenseExpiryTime.plusSeconds(graceHours * 3600L);
            
    if (now.isAfter(graceDeadline)) {
        return LicenseFileValidationResult.invalid(
                "License grace period expired at " + graceDeadline);
    }

    // 3. During grace, ensure the signed file itself hasn't expired.
    String fileExpiry = decoded.path("meta")
            .path("expiry")
            .asText(null);

    if (fileExpiry == null || fileExpiry.trim().isEmpty()) {
        return LicenseFileValidationResult.invalid(
                "License file TTL is missing");
    }

    Instant fileExpiryTime = Instant.parse(fileExpiry);

    if (now.isAfter(fileExpiryTime)) {
        return LicenseFileValidationResult.invalid(
                "License file TTL expired at " + fileExpiryTime);
    }

    return LicenseFileValidationResult.valid(
            decoded.path("data"));
}
    private static Duration graceDuration(JsonNode graceHours) {
        BigDecimal totalNanos = graceHours.decimalValue()
                .multiply(new BigDecimal("3600000000000"))
                .setScale(0, RoundingMode.HALF_UP);
        BigDecimal[] split = totalNanos.divideAndRemainder(new BigDecimal("1000000000"));
        return Duration.ofSeconds(split[0].longValueExact(), split[1].intValueExact());
    }

    private JsonNode decodePayload(String certificate) throws IOException {
        String payload = certificate
                .replace(BEGIN_LICENSE_FILE, "")
                .replace(END_LICENSE_FILE, "")
                .replaceAll("\\s", "");
        return objectMapper.readTree(Base64.getDecoder().decode(payload));
    }

    private boolean verifyEd25519(String signedData, String signature) {
        byte[] publicKeyBytes = Hex.decode(publicKeyHex);
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        byte[] signedDataBytes = signedData.getBytes(StandardCharsets.UTF_8);

        Ed25519PublicKeyParameters params = new Ed25519PublicKeyParameters(publicKeyBytes, 0);
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, params);
        verifier.update(signedDataBytes, 0, signedDataBytes.length);
        return verifier.verifySignature(signatureBytes);
    }

    public static class LicenseFileValidationResult {
        private final boolean valid;
        private final String reason;
        private final JsonNode data;

        private LicenseFileValidationResult(boolean valid, String reason, JsonNode data) {
            this.valid = valid;
            this.reason = reason;
            this.data = data;
        }

        public static LicenseFileValidationResult valid(JsonNode data) {
            return new LicenseFileValidationResult(true, null, data);
        }

        public static LicenseFileValidationResult invalid(String reason) {
            return new LicenseFileValidationResult(false, reason, null);
        }

        public boolean isValid() {
            return valid;
        }

        public String getReason() {
            return reason;
        }

        public JsonNode getData() {
            return data;
        }
    }
}

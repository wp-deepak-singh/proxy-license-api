package com.wpits.gateway.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;

@Service
public class LicenseFileService {

    private static final String BEGIN_LICENSE_FILE = "-----BEGIN LICENSE FILE-----";
    private static final String END_LICENSE_FILE = "-----END LICENSE FILE-----";
    private static final String EXPECTED_ALGORITHM = "base64+ed25519";

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final String keygenApiUrl;
    private final String accountId;
    private final String licenseId;
    private final String token;
    private final String publicKeyHex;
    private final Path storagePath;

    public LicenseFileService(
            RestTemplate restTemplate,
            ObjectMapper objectMapper,
            @Value("${keygen.api-url}") String keygenApiUrl,
            @Value("${keygen.account-id}") String accountId,
            @Value("${keygen.license-id:}") String licenseId,
            @Value("${keygen.token}") String token,
            @Value("${keygen.public-key}") String publicKeyHex,
            @Value("${keygen.storage.path:./license.lic}") String storagePath) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
        this.keygenApiUrl = keygenApiUrl;
        this.accountId = accountId;
        this.licenseId = licenseId;
        this.token = token;
        this.publicKeyHex = publicKeyHex;
        this.storagePath = Paths.get(storagePath);
    }

    public Path checkOutAndSaveLicenseFile() throws IOException {
        if (licenseId == null || licenseId.trim().isEmpty()) {
            throw new IllegalStateException("Missing keygen.license-id");
        }

        String url = keygenApiUrl + "/v1/accounts/" + accountId + "/licenses/" + licenseId + "/actions/check-out";
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.valueOf("application/vnd.api+json")));
        headers.setContentType(MediaType.valueOf("application/vnd.api+json"));
        headers.setBearerAuth(token);

        ResponseEntity<String> response = restTemplate.postForEntity(url, new HttpEntity<>("", headers), String.class);
        if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
            throw new IllegalStateException("Keygen checkout failed: " + response.getStatusCode());
        }

        JsonNode root = objectMapper.readTree(response.getBody());
        String certificate = root.path("data").path("attributes").path("certificate").asText();
        if (certificate == null || certificate.trim().isEmpty()) {
            throw new IllegalStateException("Keygen checkout response did not include a certificate");
        }

        Path parent = storagePath.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(storagePath, certificate.getBytes(StandardCharsets.UTF_8));
        return storagePath;
    }

    public LicenseFileValidationResult validateSavedLicenseFile() throws IOException {
        return validateLicenseFile(new String(Files.readAllBytes(storagePath), StandardCharsets.UTF_8));
    }

    public LicenseFileValidationResult validateLicenseFile(String certificate) throws IOException {
        JsonNode payload = decodePayload(certificate);
        String algorithm = payload.path("alg").asText();
        if (!EXPECTED_ALGORITHM.equals(algorithm)) {
            return LicenseFileValidationResult.invalid("Unsupported license file algorithm: " + algorithm);
        }

        String enc = payload.path("enc").asText();
        String sig = payload.path("sig").asText();
        if (enc.isEmpty() || sig.isEmpty()) {
            return LicenseFileValidationResult.invalid("License file payload must contain enc and sig");
        }

        if (!verifyEd25519("license/" + enc, sig)) {
            return LicenseFileValidationResult.invalid("Invalid license file signature");
        }

        JsonNode data = objectMapper.readTree(new String(Base64.getDecoder().decode(enc), StandardCharsets.UTF_8));
        String expiry = payload.path("meta").path("expiry").asText(null);
        if (expiry != null && Instant.now().isAfter(Instant.parse(expiry))) {
            return LicenseFileValidationResult.invalid("License file TTL expired at " + expiry);
        }

        return LicenseFileValidationResult.valid(data);
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

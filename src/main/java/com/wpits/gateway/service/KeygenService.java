package com.wpits.gateway.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;

@Service
public class KeygenService {

        private final RestTemplate restTemplate;
        private final String accountId;
        private final String token;
        private final String keygenApiUrl;
        private final ObjectMapper objectMapper;

        public KeygenService(
                        ObjectMapper objectMapper,

                        @Value("${keygen.account-id}") String accountId,
                        @Value("${keygen.token}") String token,
                        @Value("${keygen.api-url}") String keygenApiUrl,
                        RestTemplate restTemplate) {
                this.accountId = accountId;
                this.token = token;
                this.objectMapper = objectMapper;

                this.restTemplate = restTemplate;
                this.keygenApiUrl = keygenApiUrl;

        }

        public String fetchLicensesByProductId(String productId) {
                String url = UriComponentsBuilder
                                .fromHttpUrl("http://localhost/v1/accounts/" + accountId + "/licenses")
                                .queryParam("product", productId)
                                .queryParam("limit", 100)
                                .toUriString();

                HttpHeaders headers = new HttpHeaders();
                headers.setBearerAuth(token);
                headers.setAccept(Collections.singletonList(
                                MediaType.parseMediaType("application/vnd.api+json")));

                ResponseEntity<String> response = restTemplate.exchange(
                                url,
                                HttpMethod.GET,
                                new HttpEntity<>(headers),
                                String.class);
                return response.getBody();
        }

        public String checkOutLicenseFile(String licenseId) {
                String url = keygenApiUrl + "/v1/accounts/"
                                + accountId + "/licenses/"
                                + licenseId + "/actions/check-out";

                HttpHeaders headers = new HttpHeaders();
                headers.setBearerAuth(token);
                headers.setAccept(Collections.singletonList(
                                MediaType.parseMediaType("application/vnd.api+json")));
                headers.setContentType(
                                MediaType.parseMediaType("application/vnd.api+json"));

                ResponseEntity<String> response = restTemplate.postForEntity(
                                url,
                                new HttpEntity<>("", headers),
                                String.class);

                JsonNode root;
                try {
                        root = objectMapper.readTree(response.getBody());
                } catch (Exception e) {
                        throw new IllegalStateException(
                                        "Failed to parse Keygen checkout response", e);
                }

                String certificate = root.path("data")
                                .path("attributes")
                                .path("certificate")
                                .asText();

                if (!response.getStatusCode().is2xxSuccessful()
                                || certificate == null
                                || certificate.trim().isEmpty()) {
                        throw new IllegalStateException(
                                        "Keygen checkout did not return a certificate");
                }

                return certificate;
        }

        public String findOfflineLicenseId(String responseBody)
                        throws IOException {

                JsonNode root = objectMapper.readTree(responseBody);

                for (JsonNode license : root.path("data")) {
                        JsonNode attributes = license.path("attributes");
                        JsonNode scheme = attributes.path("scheme");
                        String expiry = attributes.path("expiry").asText("");

                        if (!scheme.isNull()
                                        && !scheme.asText().trim().isEmpty()
                                        && !expiry.trim().isEmpty()
                                        && Instant.now().isBefore(Instant.parse(expiry))) {
                                return license.path("id").asText();
                        }
                }

                throw new IllegalStateException(
                                "No unexpired offline license found");
        }

        public long getOfflineLicenseGraceHours(String productId)
        throws IOException {

    String response = fetchLicensesByProductId(productId);
    JsonNode root = objectMapper.readTree(response);

    for (JsonNode license : root.path("data")) {
        return license.path("attributes")
                .path("metadata")
                .path("graceExpiryInHours")
                .asLong(72);
    }

    throw new IllegalStateException("No license found");
}
}
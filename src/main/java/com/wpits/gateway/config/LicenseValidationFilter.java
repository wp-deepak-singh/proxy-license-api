package com.wpits.gateway.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

@Component
public class LicenseValidationFilter extends ZuulFilter {

    @Value("${keygen.api-url}")
    private String keygenApiUrl;

    @Value("${keygen.account-id}")
    private String accountId;

    @Value("${keygen.product-id}")
    private String productId;

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public LicenseValidationFilter(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    public String filterType() {
        return "pre"; // Runs before routing to microservices
    }

    @Override
    public int filterOrder() {
        return 1; // High priority check
    }

    @Override
    public boolean shouldFilter() {
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        String uri = request.getRequestURI();

        // Bypass authentication routes and actuator endpoints so clients can still log
        // in or check health
        if (uri.startsWith("/api/client/auth") || uri.startsWith("/actuator")) {
            return false;
        }

        return true;
    }

    @Override
    public Object run() {
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();

        String licenseKey = request.getHeader("X-License-Key");
        if (licenseKey == null || licenseKey.isEmpty()) {
            failRequest(ctx, "Missing 'X-License-Key' header.", HttpStatus.UNAUTHORIZED);
            return null;
        }

        try {
            LicenseValidationResult result = validateKeyForProduct(licenseKey);
            if (!result.isValid()) {
                failRequest(ctx, result.getMessage(), HttpStatus.UNAUTHORIZED);
                return null;
            }
        } catch (Exception e) {
            failRequest(ctx, "License validation exception: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }

        return null; // Passes through to microservices
    }

    private LicenseValidationResult validateKeyForProduct(String licenseKey) throws Exception {
        String url = keygenApiUrl + "/v1/accounts/" + accountId + "/licenses/actions/validate-key";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.valueOf("application/vnd.api+json"));
        headers.setAccept(Collections.singletonList(MediaType.valueOf("application/vnd.api+json")));

        Map<String, Object> scope = new HashMap<>();
        scope.put("product", productId);
        scope.put("fingerprint", getMacAddressFingerprint());


        Map<String, Object> meta = new HashMap<>();
        meta.put("key", licenseKey);
        meta.put("scope", scope);

        Map<String, Object> body = new HashMap<>();
        body.put("meta", meta);

        HttpEntity<String> entity = new HttpEntity<>(objectMapper.writeValueAsString(body), headers);
        ResponseEntity<String> response = restTemplate.postForEntity(url, entity, String.class);
        if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
            return LicenseValidationResult.invalid("Keygen validation request failed: " + response.getStatusCode());
        }

        JsonNode root = objectMapper.readTree(response.getBody());
        boolean valid = root.path("meta").path("valid").asBoolean(false);
        String code = root.path("meta").path("code").asText("");
        String detail = root.path("meta").path("detail").asText("");
        String status = root.path("data").path("attributes").path("status").asText("");

        if (!valid) {
            return LicenseValidationResult.invalid(formatValidationMessage(code, detail, status));
        }

        if ("EXPIRED".equals(status) || "SUSPENDED".equals(status) || "BANNED".equals(status)) {
            return LicenseValidationResult.invalid(formatValidationMessage(status, detail, status));
        }

        return LicenseValidationResult.valid();
    }

    private String formatValidationMessage(String code, String detail, String status) {
        StringBuilder message = new StringBuilder("License validation failed");
        if (code != null && !code.isEmpty()) {
            message.append(" [").append(code).append("]");
        }
        if (detail != null && !detail.isEmpty()) {
            message.append(": ").append(detail);
        }
        if (status != null && !status.isEmpty()) {
            message.append(" (status: ").append(status).append(")");
        }
        return message.toString();
    }

    private String getMacAddressFingerprint() throws SocketException {
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces.hasMoreElements()) {
            NetworkInterface networkInterface = interfaces.nextElement();
            byte[] hardwareAddress = networkInterface.getHardwareAddress();

            if (hardwareAddress == null || networkInterface.isLoopback() || !networkInterface.isUp()) {
                continue;
            }

            StringBuilder fingerprint = new StringBuilder();
            for (byte b : hardwareAddress) {
                if (fingerprint.length() > 0) {
                    fingerprint.append(":");
                }
                fingerprint.append(String.format("%02X", b));
            }
            return fingerprint.toString();
        }

        throw new SocketException("No active MAC address found");
    }

    private void failRequest(RequestContext ctx, String message, HttpStatus status) {
        ctx.setSendZuulResponse(false);
        ctx.setResponseStatusCode(status.value());
        ctx.setResponseBody("{\"error\": \"" + message + "\"}");
        ctx.getResponse().setContentType("application/json");
    }

    private static class LicenseValidationResult {
        private final boolean valid;
        private final String message;

        private LicenseValidationResult(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }

        static LicenseValidationResult valid() {
            return new LicenseValidationResult(true, null);
        }

        static LicenseValidationResult invalid(String message) {
            return new LicenseValidationResult(false, message);
        }

        boolean isValid() {
            return valid;
        }

        String getMessage() {
            return message;
        }
    }
}

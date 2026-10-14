package com.wpits.gateway.controller;

import com.wpits.gateway.service.KeygenService;
import com.wpits.gateway.service.LicenseFileService;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/license-file")
public class LicenseFileController {

    private final LicenseFileService licenseFileService;
    private final String productId;
    private final KeygenService keygenService;

    public LicenseFileController(LicenseFileService licenseFileService, @Value("${keygen.product-id}") String productId, KeygenService keygenService) {
        this.licenseFileService = licenseFileService;
        this.productId = productId;
        this.keygenService = keygenService;
    }

    @PostMapping("/check-out")
    public ResponseEntity<Map<String, Object>> checkOut() throws Exception {
        Path savedPath = licenseFileService.checkOutAndSaveLicenseFile("07726a83-4b3d-4b9b-adbc-f9f6c986732f");
        // keygenService.fetchLicensesByProductId(productId);
        Map<String, Object> body = new HashMap<>();
        body.put("saved", true);
        body.put("path", savedPath.toString());
        return ResponseEntity.ok(body);
    }

    @PostMapping("/validate")
    public ResponseEntity<LicenseFileService.LicenseFileValidationResult> validate() throws Exception {
        LicenseFileService.LicenseFileValidationResult result = licenseFileService.validateSavedLicenseFile();
        return result.isValid() ? ResponseEntity.ok(result) : ResponseEntity.status(401).body(result);
    }
}

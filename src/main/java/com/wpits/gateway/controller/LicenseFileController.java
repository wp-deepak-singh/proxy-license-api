package com.wpits.gateway.controller;

import com.wpits.gateway.service.LicenseFileService;
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

    public LicenseFileController(LicenseFileService licenseFileService) {
        this.licenseFileService = licenseFileService;
    }

    @PostMapping("/check-out")
    public ResponseEntity<Map<String, Object>> checkOut() throws Exception {
        Path savedPath = licenseFileService.checkOutAndSaveLicenseFile();
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

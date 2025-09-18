package com.example.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/csp")
@ConditionalOnProperty(name = "security.csp.report-uri")
public class CspReportController {

    private static final Logger logger = LoggerFactory.getLogger(CspReportController.class);

    @PostMapping("/report")
    public ResponseEntity<Void> handleCspReport(@RequestBody JsonNode reportData) {
        logger.warn("CSP Violation Report: {}", reportData);
        
        // Extract useful information from the report
        if (reportData.has("csp-report")) {
            JsonNode cspReport = reportData.get("csp-report");
            String violatedDirective = cspReport.path("violated-directive").asText();
            String blockedUri = cspReport.path("blocked-uri").asText();
            String documentUri = cspReport.path("document-uri").asText();
            
            logger.warn("CSP Violation - Directive: {}, Blocked URI: {}, Document: {}", 
                       violatedDirective, blockedUri, documentUri);
        }
        
        // Here you could:
        // - Store the report in a database
        // - Send it to a monitoring service (e.g., Sentry, DataDog)
        // - Process it for security analysis
        // - Send alerts for critical violations
        
        return ResponseEntity.ok().build();
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("CSP service is running");
    }

    @GetMapping("/nonce")
    public ResponseEntity<String> getCurrentNonce(HttpServletRequest request) {
        String nonce = (String) request.getAttribute("cspNonce");
        if (nonce != null) {
            return ResponseEntity.ok(nonce);
        }
        return ResponseEntity.notFound().build();
    }
}
package com.example.config;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.csp")
public class CspProperties {

	private boolean enabled;
	private boolean reportOnly;
	private String reportUri;
	private String nonce;
	
	private boolean generateNonce;
	private Map<String, List<String>> directives = new HashMap<>();

	public CspProperties() {
        directives.put("default-src", List.of("'self'"));
        directives.put("script-src", List.of("'self'", "'unsafe-inline'"));
        directives.put("style-src", List.of("'self'", "'unsafe-inline'"));
        directives.put("img-src", List.of("'self'", "data:", "https:"));
        directives.put("font-src", List.of("'self'", "https:"));
        directives.put("connect-src", List.of("'self'"));
        directives.put("frame-ancestors", List.of("'none'"));
        directives.put("base-uri", List.of("'self'"));
        directives.put("form-action", List.of("'self'"));
    }
	
	public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isReportOnly() {
        return reportOnly;
    }

    public void setReportOnly(boolean reportOnly) {
        this.reportOnly = reportOnly;
    }

    public String getReportUri() {
        return reportUri;
    }

    public void setReportUri(String reportUri) {
        this.reportUri = reportUri;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public boolean isGenerateNonce() {
        return generateNonce;
    }

    public void setGenerateNonce(boolean generateNonce) {
        this.generateNonce = generateNonce;
    }

    public Map<String, List<String>> getDirectives() {
        return directives;
    }

    public void setDirectives(Map<String, List<String>> directives) {
        this.directives = directives;
    }

    public String buildCspHeader(String dynamicNonce) {
        StringBuilder csp = new StringBuilder();
        
        directives.forEach((directive, sources) -> {
            if (!sources.isEmpty()) {
                csp.append(directive).append(" ");
                
                // For strict-dynamic, nonce is required for script-src
                if (generateNonce && dynamicNonce != null) {
                    if (directive.equals("script-src")) {
                        // With strict-dynamic, we need nonce and the directive itself
                        csp.append("'nonce-").append(dynamicNonce).append("' ");
                        // strict-dynamic should be last to override other sources for modern browsers
                        String sourcesStr = String.join(" ", sources);
                        if (sourcesStr.contains("'strict-dynamic'")) {
                            // Add other sources first, then strict-dynamic
                            String otherSources = sourcesStr.replace("'strict-dynamic'", "").trim();
                            if (!otherSources.isEmpty()) {
                                csp.append(otherSources).append(" ");
                            }
                            csp.append("'strict-dynamic'");
                        } else {
                            csp.append(sourcesStr);
                        }
                    } else if (directive.equals("style-src")) {
                        // For styles, add nonce but keep other sources
                        csp.append("'nonce-").append(dynamicNonce).append("' ");
                        csp.append(String.join(" ", sources));
                    } else {
                        csp.append(String.join(" ", sources));
                    }
                } else {
                    csp.append(String.join(" ", sources));
                }
                
                csp.append("; ");
            }
        });

        if (reportUri != null && !reportUri.trim().isEmpty()) {
            csp.append("report-uri ").append(reportUri).append("; ");
        }

        return csp.toString().trim();
    }
}

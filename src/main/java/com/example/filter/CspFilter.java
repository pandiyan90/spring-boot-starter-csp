package com.example.filter;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.example.config.CspProperties;
import com.example.service.NonceGenerator;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CspFilter implements Filter {

	private static final Logger logger = LoggerFactory.getLogger(CspFilter.class);
    private static final String CSP_HEADER = "Content-Security-Policy";
    private static final String CSP_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only";
    private static final String NONCE_ATTRIBUTE = "cspNonce";

    private final CspProperties cspProperties;
    private final NonceGenerator nonceGenerator;

    public CspFilter(CspProperties cspProperties, NonceGenerator nonceGenerator) {
        this.cspProperties = cspProperties;
        this.nonceGenerator = nonceGenerator;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        if (cspProperties.isEnabled() && response instanceof HttpServletResponse httpResponse
            && request instanceof HttpServletRequest httpRequest) {
            
            String nonce = null;
            if (cspProperties.isGenerateNonce()) {
                nonce = nonceGenerator.generateNonce();
                httpRequest.setAttribute(NONCE_ATTRIBUTE, nonce);
            }
            
            String cspValue = cspProperties.buildCspHeader(nonce);
            String headerName = cspProperties.isReportOnly() ? CSP_REPORT_ONLY_HEADER : CSP_HEADER;
            
            httpResponse.setHeader(headerName, cspValue);
            logger.debug("Added CSP header: {} = {}", headerName, cspValue);
        }
        
        chain.doFilter(request, response);
    }
}

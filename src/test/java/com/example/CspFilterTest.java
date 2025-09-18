package com.example;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.example.config.CspProperties;
import com.example.filter.CspFilter;
import com.example.service.NonceGenerator;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;

public class CspFilterTest {

	private CspFilter cspFilter;
    private CspProperties cspProperties;
    private NonceGenerator nonceGenerator;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        cspProperties = new CspProperties();
        nonceGenerator = mock(NonceGenerator.class);
        filterChain = mock(FilterChain.class);
        cspFilter = new CspFilter(cspProperties, nonceGenerator);
    }

    @Test
    void shouldAddCspHeaderWhenEnabled() throws IOException, ServletException {
        // Given
        cspProperties.setEnabled(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        // When
        cspFilter.doFilter(request, response, filterChain);

        // Then
        assertThat(response.getHeader("Content-Security-Policy"));
        assertThat(response.getHeader("Content-Security-Policy").contains("default-src 'self'"));
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotAddCspHeaderWhenDisabled() throws IOException, ServletException {
        // Given
        cspProperties.setEnabled(false);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        // When
        cspFilter.doFilter(request, response, filterChain);

        // Then
        assertThat(response.getHeader("Content-Security-Policy"));
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldUseReportOnlyHeaderWhenConfigured() throws IOException, ServletException {
        // Given
        cspProperties.setEnabled(true);
        cspProperties.setReportOnly(true);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        // When
        cspFilter.doFilter(request, response, filterChain);

        // Then
        assertThat(response.getHeader("Content-Security-Policy-Report-Only"));
        assertThat(response.getHeader("Content-Security-Policy"));
    }

    @Test
    void shouldGenerateNonceWhenEnabled() throws IOException, ServletException {
        // Given
        cspProperties.setEnabled(true);
        cspProperties.setGenerateNonce(true);
        cspProperties.getDirectives().put("script-src", List.of("'self'"));
        
        when(nonceGenerator.generateNonce()).thenReturn("abc123");
        
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        // When
        cspFilter.doFilter(request, response, filterChain);

        // Then
        String cspHeader = response.getHeader("Content-Security-Policy");
        assertThat(cspHeader);
        assertThat(cspHeader.contains("'nonce-abc123'"));
    }

}

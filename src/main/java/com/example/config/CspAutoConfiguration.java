package com.example.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.core.Ordered;

import com.example.filter.CspFilter;
import com.example.service.NonceGenerator;

@AutoConfiguration
@ConditionalOnWebApplication
@ConditionalOnProperty(name = "security.csp.enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(CspProperties.class)
@ComponentScan(basePackages = "com.example")
public class CspAutoConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(CspAutoConfiguration.class);

    @Bean
    NonceGenerator nonceGenerator() {
        return new NonceGenerator();
    }

    @Bean
    FilterRegistrationBean<CspFilter> cspFilterRegistration(
            CspProperties cspProperties, NonceGenerator nonceGenerator) {
        
        logger.info("Registering CSP Filter with properties: enabled={}, reportOnly={}, generateNonce={}", 
                   cspProperties.isEnabled(), cspProperties.isReportOnly(), cspProperties.isGenerateNonce());
        
        FilterRegistrationBean<CspFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new CspFilter(cspProperties, nonceGenerator));
        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
        registrationBean.setName("cspFilter");
        
        return registrationBean;
    }
}
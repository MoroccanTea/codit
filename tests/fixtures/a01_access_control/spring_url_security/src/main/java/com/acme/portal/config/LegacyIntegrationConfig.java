package com.acme.portal.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;

/**
 * Kept for the old SOAP bridge, which authenticates on its own (it does not, any more).
 */
@Configuration
public class LegacyIntegrationConfig {

    @Bean
    public WebSecurityCustomizer legacyBridgeCustomizer() {
        return web -> web.ignoring().requestMatchers("/**");   // codit-expect: CWE-862 web.ignoring() of /** removes Spring Security from every path
    }
}

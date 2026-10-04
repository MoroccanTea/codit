package com.acme.portal.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class WebCorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration api = new CorsConfiguration();
        api.setAllowedOriginPatterns(List.of("*"));   // codit-expect: CWE-942 any origin pattern combined with setAllowCredentials(true)
        api.setAllowCredentials(true);
        api.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));

        CorsConfiguration partner = new CorsConfiguration();
        partner.setAllowedMethods(List.of("GET"));
        partner.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        partner.setAllowedOrigins(List.of("https://partner.acme.com"));   // codit-safe: CWE-942 explicit origin allow-list with credentials
        partner.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", api);
        source.registerCorsConfiguration("/partner/**", partner);
        return source;
    }
}

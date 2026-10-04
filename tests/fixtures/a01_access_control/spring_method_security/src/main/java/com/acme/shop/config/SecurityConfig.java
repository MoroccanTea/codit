package com.acme.shop.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig {

    /** Endpoints that must stay reachable without a token. Everything else needs a valid JWT. */
    private static final String[] PUBLIC_ENDPOINTS = {
            "/auth/login",
            "/auth/forgot-password",
            "/actuator/health"
    };

    @Bean
    public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers(PUBLIC_ENDPOINTS).permitAll()   // codit-safe: CWE-862 explicit whitelist (login, forgot-password, health) then anyRequest().authenticated()
                .anyRequest().authenticated());

        // Pure bearer-token API: no cookies, no server-side session.
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.oauth2ResourceServer(oauth -> oauth.jwt(withDefaults()));

        // CSRF protection is meaningless for a stateless Authorization-header API.
        http.csrf(csrf -> csrf.disable());   // codit-safe: CWE-352 stateless JWT resource server (STATELESS + oauth2ResourceServer), no cookie session

        return http.build();
    }
}

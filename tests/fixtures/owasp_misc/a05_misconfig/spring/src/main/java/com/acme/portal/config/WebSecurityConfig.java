package com.acme.portal.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    /** Legacy JSP portal, form login with a session cookie. */
    @Bean
    @Order(1)
    public SecurityFilterChain legacyPortal(HttpSecurity http) throws Exception {
        http.securityMatcher("/portal/**")
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            // codit-expect: CWE-352 CSRF protection disabled on a cookie-session form application
            .csrf(csrf -> csrf.disable())



            // codit-expect: CWE-16 all security response headers disabled
            .headers(headers -> headers.disable())



            // codit-expect: CWE-942 any origin allowed together with credentials
            .cors(cors -> cors.configurationSource(legacyCors()));
        return http.build();
    }

    private UrlBasedCorsConfigurationSource legacyCors() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOriginPatterns(List.of("*"));
        cfg.setAllowCredentials(true);
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
        src.registerCorsConfiguration("/**", cfg);
        return src;
    }

    /** Admin console (embedded reporting iframe). */
    @Bean
    @Order(2)
    public SecurityFilterChain adminConsole(HttpSecurity http) throws Exception {
        http.securityMatcher("/admin/**")
            .authorizeHttpRequests(auth -> auth.anyRequest().hasRole("ADMIN"))
            .formLogin(Customizer.withDefaults())
            // codit-expect: CWE-16 X-Frame-Options disabled (clickjacking on the admin console)
            .headers(headers -> headers.frameOptions(frame -> frame.disable()));
        return http.build();
    }

    /** Current application. */
    @Bean
    @Order(3)
    public SecurityFilterChain app(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            // codit-safe: CWE-352 CSRF enabled with a cookie token repository; only signed webhooks are exempt
            .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).ignoringRequestMatchers("/webhooks/stripe"))



            // codit-safe: CWE-16 frame options restricted to same origin, HSTS on
            .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()).httpStrictTransportSecurity(Customizer.withDefaults()))



            // codit-safe: CWE-942 single trusted origin
            .cors(cors -> cors.configurationSource(appCors()));
        return http.build();
    }

    private UrlBasedCorsConfigurationSource appCors() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(List.of("https://app.acme.example"));
        cfg.setAllowCredentials(true);
        cfg.setAllowedMethods(List.of("GET", "POST"));
        UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
        src.registerCorsConfiguration("/**", cfg);
        return src;
    }
}

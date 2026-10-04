package com.acme.auth.security;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    @Primary
    public PasswordEncoder passwordEncoder() {
        // codit-safe: CWE-916 bcrypt cost 12 for every new password hash
        return new BCryptPasswordEncoder(12);
    }

    /** Hashes imported from the 2019 platform, re-hashed with the primary encoder after login. */
    @Bean("legacyPasswordEncoder")
    public PasswordEncoder legacyPasswordEncoder() {
        // codit-expect: CWE-916 bcrypt cost factor 4 is far too fast for password storage
        return new BCryptPasswordEncoder(4);
    }

    /** Shared secrets of partner integrations. */
    @Bean("partnerSecretEncoder")
    public PasswordEncoder partnerSecretEncoder() {
        // codit-expect: CWE-256 NoOpPasswordEncoder stores and compares partner secrets in plaintext
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public UserDetailsService actuatorUsers() {
        UserDetails ops = User.withUsername("ops")
                // codit-expect: CWE-256 {noop} prefix keeps the actuator password in plaintext
                .password("{noop}" + System.getenv("ACTUATOR_PASSWORD"))
                .roles("OPS")
                .build();
        return new InMemoryUserDetailsManager(ops);
    }

    @Bean
    @Order(1)
    public SecurityFilterChain legacyApi(HttpSecurity http, JwtService jwtService) throws Exception {
        http.securityMatcher("/api/v1/**")
                .csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/api/v1/auth/**").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(new LegacyTokenFilter(jwtService), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain api(HttpSecurity http, JwtService jwtService) throws Exception {
        http.securityMatcher("/api/v2/**")
                // codit-safe: CWE-352 stateless bearer-token API (no cookie session), CSRF protection not applicable
                .csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/api/v2/auth/login", "/api/v2/auth/password-reset/**").permitAll()
                        .requestMatchers("/api/v2/auth/2fa/**").hasAuthority("MFA_PENDING")
                        .anyRequest().hasRole("USER"))
                .addFilterBefore(new JwtAuthenticationFilter(jwtService), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    @Order(3)
    public SecurityFilterChain actuator(HttpSecurity http,
                                        @Qualifier("actuatorUsers") UserDetailsService actuatorUsers) throws Exception {
        http.securityMatcher("/actuator/**")
                .userDetailsService(actuatorUsers)
                .httpBasic(b -> { })
                .authorizeHttpRequests(a -> a.anyRequest().hasRole("OPS"));
        return http.build();
    }
}

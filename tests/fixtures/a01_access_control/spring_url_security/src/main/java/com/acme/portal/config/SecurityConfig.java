package com.acme.portal.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Customer portal: server-rendered pages with a JSESSIONID cookie session (formLogin).
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final PortalProperties props;

    public SecurityConfig(PortalProperties props) {
        this.props = props;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain adminChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/admin/**")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/admin/**").hasRole("ADMIN"))   // codit-safe: CWE-862 URL-level role rule protects every AdminController handler
            .formLogin(withDefaults());
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/**")
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/**").permitAll())   // codit-expect: CWE-862 whole /api surface (customers, invoices) opened to anonymous callers
            .httpBasic(withDefaults());
        return http.build();
    }

    @Bean
    @Order(3)
    public SecurityFilterChain webChain(HttpSecurity http) throws Exception {
        http.formLogin(form -> form.loginPage("/login").permitAll())   // codit-safe: CWE-862 permitAll() scoped to the login page of formLogin
            .logout(withDefaults())
            .sessionManagement(session -> session.sessionFixation().migrateSession());

        // TODO re-enable once the React widgets send the X-XSRF-TOKEN header
        http.csrf(csrf -> csrf.disable());   // codit-expect: CWE-352 CSRF disabled on a cookie-session (formLogin) chain

        boolean demo = props.isDemoMode();
        if (demo) {
            // demo kiosk build: everything open
            http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());   // codit-expect: CWE-862 anyRequest().permitAll() in the demo branch
            return http.build();
        }

        // regular deployments
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/css/**", "/js/**", "/favicon.ico").permitAll()   // codit-safe: CWE-862 only login page and static assets are public; rest authenticated
                .requestMatchers(HttpMethod.GET, "/docs/**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    public WebSecurityCustomizer ignoreStaticResources() {
        return web -> web.ignoring().requestMatchers("/static/**", "/webjars/**");   // codit-safe: CWE-862 only static asset paths bypass the filter chain
    }
}

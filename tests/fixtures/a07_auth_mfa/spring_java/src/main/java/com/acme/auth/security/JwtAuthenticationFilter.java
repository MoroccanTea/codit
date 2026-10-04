package com.acme.auth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Bearer token filter registered for /api/v2/**.
 * A 2FA_PENDING token is only usable on the second-factor endpoints.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final List<String> PENDING_ALLOWED = List.of("/api/v2/auth/2fa/verify", "/api/v2/auth/2fa/sms/send");

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }
        try {
            Claims claims = jwtService.parse(header.substring(7));
            String purpose = claims.get(JwtService.PURPOSE_CLAIM, String.class);
            if (JwtService.PURPOSE_2FA_PENDING.equals(purpose)) {
                if (!PENDING_ALLOWED.contains(request.getRequestURI())) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Second factor required");
                    return;
                }
                SecurityContextHolder.getContext().setAuthentication(
                        new UsernamePasswordAuthenticationToken(new PendingPrincipal(Long.valueOf(claims.getSubject())),
                                null, List.of(new SimpleGrantedAuthority("MFA_PENDING"))));
            } else if (JwtService.PURPOSE_ACCESS.equals(purpose)) {
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                        claims.getSubject(), null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
                // codit-safe: CWE-308 only purpose=ACCESS tokens become a full authentication, pending tokens are confined
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        } catch (JwtException e) {
            SecurityContextHolder.clearContext();
        }
        chain.doFilter(request, response);
    }
}

package demo;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;

    public JwtAuthFilter(JwtUtil jwtUtil, CustomUserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            Claims claims = jwtUtil.parseClaims(header.substring(7));
            boolean pending2FA = JwtUtil.PURPOSE_2FA_PENDING.equals(claims.get(JwtUtil.CLAIM_PURPOSE, String.class))
                    || Boolean.TRUE.equals(claims.get("require2FA", Boolean.class));
            if (pending2FA && !request.getRequestURI().endsWith("/auth/login-2fa")) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
            UserDetails user = userDetailsService.loadUserByUsername(claims.getSubject());
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities()));
        }
        chain.doFilter(request, response);
    }
}

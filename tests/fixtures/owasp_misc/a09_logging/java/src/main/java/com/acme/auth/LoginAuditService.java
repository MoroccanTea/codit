package com.acme.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

@Service
public class LoginAuditService {

    private static final Logger log = LoggerFactory.getLogger(LoginAuditService.class);

    private final AuthenticationManager authenticationManager;
    private final SecurityEventPublisher events;

    public LoginAuditService(AuthenticationManager authenticationManager, SecurityEventPublisher events) {
        this.authenticationManager = authenticationManager;
        this.events = events;
    }

    public Authentication loginLegacy(String username, String password) {
        Authentication result = null;
        try {
            result = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        // codit-expect: CWE-390 authentication failure swallowed silently (no log, no audit event, null returned)
        } catch (AuthenticationException e) {
        }
        return result;
    }



    public Authentication login(String username, String password) {
        try {
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        // codit-safe: CWE-390 failure recorded as a security event and rethrown
        } catch (AuthenticationException e) {
            events.loginFailed(sanitize(username));
            throw e;
        }
    }

    public void recordLockout(String username, String clientIp) {
        // codit-expect: CWE-117 raw username (may contain CR/LF) concatenated into the log line
        log.warn("Account locked for user " + username + " from " + clientIp);
    }



    public void recordLockoutSafe(String username, String clientIp) {
        // codit-safe: CWE-117 CR/LF stripped before logging
        log.warn("Account locked for user {} from {}", sanitize(username), sanitize(clientIp));
    }

    public void recordResetIssued(String email, String resetToken) {
        // codit-expect: CWE-532 password-reset token written to the log
        log.info("Password reset token for {}: {}", sanitize(email), resetToken);
    }



    public void recordResetIssuedSafe(long userId) {
        // codit-safe: CWE-532 only the user id is logged
        log.info("Password reset token issued for user id {}", userId);
    }

    private static String sanitize(String value) {
        return value == null ? "" : value.replaceAll("[\r\n\t]", "_");
    }

    public interface SecurityEventPublisher {
        void loginFailed(String username);
    }
}

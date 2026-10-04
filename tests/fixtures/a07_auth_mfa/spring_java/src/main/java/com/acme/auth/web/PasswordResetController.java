package com.acme.auth.web;

import com.acme.auth.domain.PasswordResetToken;
import com.acme.auth.domain.PasswordResetTokenRepository;
import com.acme.auth.domain.User;
import com.acme.auth.domain.UserRepository;
import com.acme.auth.mail.Mailer;
import com.acme.auth.security.JwtService;
import com.acme.auth.security.SessionRegistry;
import com.acme.auth.web.dto.ResetConfirmRequest;
import com.acme.auth.web.dto.ResetRequest;
import jakarta.validation.Valid;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Random;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api")
public class PasswordResetController {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetController.class);

    private final SecureRandom secureRandom = new SecureRandom();
    private final UserRepository users;
    private final PasswordResetTokenRepository resetTokens;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final SessionRegistry sessions;
    private final Mailer mailer;

    public PasswordResetController(UserRepository users, PasswordResetTokenRepository resetTokens,
                                   PasswordEncoder passwordEncoder, JwtService jwtService,
                                   SessionRegistry sessions, Mailer mailer) {
        this.users = users;
        this.resetTokens = resetTokens;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.sessions = sessions;
        this.mailer = mailer;
    }

    // ------------------------------------------------------------------ v1

    @PostMapping("/v1/auth/password-reset/request")
    public ResponseEntity<?> requestLegacy(@RequestBody ResetRequest req) {
        User user = users.findByEmail(req.email()).orElse(null);
        if (user == null) {
            return ResponseEntity.accepted().build();
        }
        // codit-expect: CWE-338 reset token built from the clock and java.util.Random
        String token = Long.toHexString(System.currentTimeMillis()) + new Random().nextInt(10_000);
        resetTokens.save(new PasswordResetToken(user, token, null));
        mailer.sendPasswordReset(user.getEmail(), token);

        // codit-expect: CWE-532 password reset token logged in clear text
        log.info("Password reset token for {}: {}", user.getEmail(), token);
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/v1/auth/password-reset/confirm")
    public ResponseEntity<?> confirmLegacy(@RequestBody ResetConfirmRequest req) {
        // codit-expect: CWE-640 reset token looked up without any expiry or single-use check
        PasswordResetToken token = resetTokens.findByToken(req.token())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid token"));
        User user = token.getUser();
        user.setPasswordHash(passwordEncoder.encode(req.newPassword()));
        users.save(user);

        // codit-expect: CWE-640 completing a reset hands out a full access token and skips the 2FA step
        return ResponseEntity.ok(Map.of("accessToken", jwtService.generateAccessToken(user)));
    }

    // ------------------------------------------------------------------ v2

    @PostMapping("/v2/auth/password-reset/request")
    public ResponseEntity<Void> request(@Valid @RequestBody ResetRequest req) {
        users.findByEmail(req.email()).ifPresent(user -> {
            byte[] raw = new byte[32];
            secureRandom.nextBytes(raw);
            String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
            Instant expiresAt = Instant.now().plus(Duration.ofMinutes(30));
            // codit-safe: CWE-916 SHA-256 of a 256-bit random reset token (not a password) is appropriate
            resetTokens.save(new PasswordResetToken(user, sha256Hex(token), expiresAt));
            mailer.sendPasswordReset(user.getEmail(), token);
        });
        log.info("password reset requested");
        // codit-safe: CWE-204 identical 202 response whether or not the account exists
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/v2/auth/password-reset/confirm")
    public ResponseEntity<Void> confirm(@Valid @RequestBody ResetConfirmRequest req) {
        String tokenHash = sha256Hex(req.token());
        // codit-safe: CWE-640 hashed, single-use token that is rejected after expiresAt
        PasswordResetToken token = resetTokens.findByTokenHashAndUsedFalseAndExpiresAtAfter(tokenHash, Instant.now())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired token"));
        User user = token.getUser();
        user.setPasswordHash(passwordEncoder.encode(req.newPassword()));
        token.setUsed(true);
        resetTokens.save(token);
        users.save(user);
        sessions.revokeAll(user.getId());
        log.info("password reset completed for user {}", user.getId());
        // codit-safe: CWE-640 no session is issued, the user must sign in again with password and 2FA
        return ResponseEntity.noContent().build();
    }

    private static String sha256Hex(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}

package com.acme.auth.web;

import com.acme.auth.domain.User;
import com.acme.auth.domain.UserRepository;
import com.acme.auth.mfa.MfaAttemptService;
import com.acme.auth.mfa.OtpChallengeStore;
import com.acme.auth.mfa.OtpSender;
import com.acme.auth.mfa.TotpService;
import com.acme.auth.mfa.TrustedDeviceService;
import com.acme.auth.security.JwtService;
import com.acme.auth.security.LoginAttemptService;
import com.acme.auth.security.PendingPrincipal;
import com.acme.auth.web.dto.LoginRequest;
import com.acme.auth.web.dto.MfaChallengeResponse;
import com.acme.auth.web.dto.OtpVerifyRequest;
import com.acme.auth.web.dto.TokenResponse;
import jakarta.validation.Valid;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * v2 authentication API: password step -> 2FA_PENDING token -> TOTP/SMS step -> access token.
 */
@RestController
@RequestMapping("/api/v2/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final SecureRandom secureRandom = new SecureRandom();
    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TotpService totpService;
    private final OtpSender otpSender;
    private final OtpChallengeStore otpStore;
    private final MfaAttemptService mfaAttempts;
    private final LoginAttemptService loginAttempts;
    private final TrustedDeviceService trustedDevices;

    public AuthController(UserRepository users, PasswordEncoder passwordEncoder, JwtService jwtService,
                          TotpService totpService, OtpSender otpSender, OtpChallengeStore otpStore,
                          MfaAttemptService mfaAttempts, LoginAttemptService loginAttempts,
                          TrustedDeviceService trustedDevices) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.totpService = totpService;
        this.otpSender = otpSender;
        this.otpStore = otpStore;
        this.mfaAttempts = mfaAttempts;
        this.loginAttempts = loginAttempts;
        this.trustedDevices = trustedDevices;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req,
                                   @CookieValue(value = "td", required = false) String deviceToken) {
        if (loginAttempts.isBlocked(req.getEmail())) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Try again later");
        }
        Optional<User> found = users.findByEmail(req.getEmail());
        if (found.isEmpty() || !passwordEncoder.matches(req.getPassword(), found.get().getPasswordHash())) {
            loginAttempts.recordFailure(req.getEmail());
            // codit-safe: CWE-204 one generic message for unknown account and wrong password
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password");
        }
        User user = found.get();
        loginAttempts.reset(req.getEmail());

        // codit-safe: CWE-807 remember-device token is random, stored hashed server-side and bound to the user
        boolean trusted = deviceToken != null && trustedDevices.isTrusted(user.getId(), deviceToken);

        if (user.isTwoFactorEnabled() && !trusted) {
            log.info("password step ok, second factor required for user {}", user.getId());
            // codit-safe: CWE-308 only a 5-minute purpose=2FA_PENDING token is issued before the second factor
            String pendingToken = jwtService.generate2FAPendingToken(user);
            return ResponseEntity.ok(new MfaChallengeResponse(true, pendingToken));
        }
        return ResponseEntity.ok(new TokenResponse(jwtService.generateAccessToken(user)));
    }

    @PostMapping("/2fa/sms/send")
    public ResponseEntity<Void> sendSmsCode(@AuthenticationPrincipal PendingPrincipal pending) {
        User user = users.findById(pending.userId()).orElseThrow();
        // codit-safe: CWE-338 SMS code drawn from SecureRandom
        String code = String.format("%06d", secureRandom.nextInt(1_000_000));
        otpStore.save(user.getId(), passwordEncoder.encode(code), Duration.ofMinutes(5));
        otpSender.sendSms(user.getPhone(), "Your Acme code is " + code);

        // codit-safe: CWE-532 log line records the event, not the code
        log.info("2FA SMS code sent to user {}", user.getId());
        mfaAttempts.reset(user.getId());
        otpStore.touch(user.getId());

        // codit-safe: CWE-308 code is delivered only by SMS and never echoed back in the response
        return ResponseEntity.accepted().build();
    }

    // codit-safe: CWE-307 attempts are counted per user and locked after 5 failures
    @PostMapping("/2fa/verify")
    public ResponseEntity<TokenResponse> verify2fa(@AuthenticationPrincipal PendingPrincipal pending,
                                                   @Valid @RequestBody OtpVerifyRequest req) {
        if (mfaAttempts.isLocked(pending.userId())) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Too many attempts");
        }
        User user = users.findById(pending.userId()).orElseThrow();
        boolean ok = totpService.verify(user.getTotpSecret(), req.getCode())
                || otpStore.matchesAndConsume(user.getId(), req.getCode(), passwordEncoder);
        if (!ok) {
            mfaAttempts.recordFailure(pending.userId());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid code");
        }
        mfaAttempts.reset(pending.userId());
        log.info("second factor verified for user {}", user.getId());
        // codit-safe: CWE-308 full access token only after the second factor was verified server-side
        return ResponseEntity.ok(new TokenResponse(jwtService.generateAccessToken(user)));
    }
}

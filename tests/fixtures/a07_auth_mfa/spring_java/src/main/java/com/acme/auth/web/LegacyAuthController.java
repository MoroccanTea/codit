package com.acme.auth.web;

import com.acme.auth.domain.User;
import com.acme.auth.domain.UserRepository;
import com.acme.auth.mfa.OtpSender;
import com.acme.auth.mfa.TotpService;
import com.acme.auth.security.JwtService;
import com.acme.auth.web.dto.LoginRequest;
import com.acme.auth.web.dto.OtpVerifyRequest;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.Map;
import java.util.Random;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * v1 authentication API, still used by the 2.x mobile application.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class LegacyAuthController {

    private static final Logger log = LoggerFactory.getLogger(LegacyAuthController.class);

    private final Random random = new Random();
    private final UserRepository users;
    private final JwtService jwtService;
    private final TotpService totpService;
    private final OtpSender otpSender;

    public LegacyAuthController(UserRepository users, JwtService jwtService,
                                TotpService totpService, OtpSender otpSender) {
        this.users = users;
        this.jwtService = jwtService;
        this.totpService = totpService;
        this.otpSender = otpSender;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req,
                                   @CookieValue(value = "trusted_device", required = false) String trustedDevice) {
        User user = users.findByEmail(req.getEmail())
                // codit-expect: CWE-204 unknown e-mail gets a distinct 404 message (account enumeration)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No account registered with this email"));

        log.debug("login attempt for user id {}", user.getId());
        user.setLastLoginAttempt(Instant.now());

        // codit-expect: CWE-256 stored password compared in plaintext with the submitted one
        if (!user.getPassword().equals(req.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Wrong password");
        }

        boolean mfaRequired = user.isTwoFactorEnabled();
        // codit-expect: CWE-807 second factor skipped when the unsigned trusted_device cookie equals 1
        if (mfaRequired && "1".equals(trustedDevice)) {
            mfaRequired = false;
        }

        if (mfaRequired) {
            users.save(user);
            // codit-expect: CWE-308 full access JWT issued at the password step, client is only told mfaRequired
            String accessToken = jwtService.generateAccessToken(user);
            return ResponseEntity.ok(Map.of("mfaRequired", true, "accessToken", accessToken));
        }

        users.save(user);
        return ResponseEntity.ok(Map.of("accessToken", jwtService.generateAccessToken(user)));
    }

    @PostMapping("/otp/send")
    public ResponseEntity<?> sendOtp(@RequestBody Map<String, String> body) {
        User user = users.findByEmail(body.get("email")).orElseThrow();
        // codit-expect: CWE-338 SMS one-time code drawn from java.util.Random
        String otp = String.format("%06d", random.nextInt(1_000_000));
        user.setPendingOtp(otp);
        user.setPendingOtpCreatedAt(Instant.now());
        users.save(user);

        // codit-expect: CWE-532 one-time code written to the application log
        log.info("Sending login OTP {} to {}", otp, user.getPhone());
        otpSender.sendSms(user.getPhone(), "Your Acme code is " + otp);

        // the 2.x app pre-fills the input field with this value
        // codit-expect: CWE-308 OTP echoed back to the client in the JSON response
        return ResponseEntity.ok(Map.of("sent", true, "otp", otp));
    }

    // codit-expect: CWE-307 OTP verification endpoint without attempt counter, lockout or rate limit
    @PostMapping("/otp/verify")
    public ResponseEntity<?> verifyOtp(@RequestBody OtpVerifyRequest req, HttpServletRequest http) {
        User user = users.findByEmail(req.getEmail()).orElseThrow();
        String mfaHeader = http.getHeader("X-MFA-Verified");

        // codit-expect: CWE-807 MFA treated as done when the client sends X-MFA-Verified: true
        if ("true".equalsIgnoreCase(mfaHeader)) {
            return ResponseEntity.ok(Map.of("accessToken", jwtService.generateAccessToken(user)));
        }

        String pending = user.getPendingOtp();
        // codit-expect: CWE-308 stored SMS code never compared with its creation time (no expiry)
        if (pending != null && pending.equals(req.getCode())) {
            user.setPendingOtp(null);
            users.save(user);
            return ResponseEntity.ok(Map.of("accessToken", jwtService.generateAccessToken(user)));
        }

        if (totpService.verifyLegacy(user.getTotpSecret(), req.getCode())) {
            return ResponseEntity.ok(Map.of("accessToken", jwtService.generateAccessToken(user)));
        }
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid code");
    }
}

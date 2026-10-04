package com.acme.shop.web;

import com.acme.shop.domain.ForgotPasswordRequest;
import com.acme.shop.domain.LoginRequest;
import com.acme.shop.domain.TokenResponse;
import com.acme.shop.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Anonymous authentication endpoints, whitelisted in SecurityConfig.PUBLIC_ENDPOINTS.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")   // codit-safe: CWE-862 intentionally public (permitAll whitelist), it is how a token is obtained
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request.email(), request.password());
    }

    @PostMapping("/forgot-password")   // codit-safe: CWE-862 intentionally public (permitAll whitelist), always answers 202
    public ResponseEntity<Void> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.sendResetLinkIfAccountExists(request.email());
        return ResponseEntity.accepted().build();
    }
}

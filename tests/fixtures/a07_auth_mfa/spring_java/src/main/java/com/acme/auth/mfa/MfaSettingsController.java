package com.acme.auth.mfa;

import com.acme.auth.domain.User;
import com.acme.auth.domain.UserRepository;
import com.acme.auth.security.UserPrincipal;
import com.acme.auth.web.dto.Disable2faRequest;
import com.acme.auth.web.dto.ProfileUpdateRequest;
import com.acme.auth.web.dto.UserDto;
import jakarta.validation.Valid;
import org.springframework.beans.BeanUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api")
public class MfaSettingsController {

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final TotpService totpService;

    public MfaSettingsController(UserRepository users, PasswordEncoder passwordEncoder, TotpService totpService) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.totpService = totpService;
    }

    // codit-expect: CWE-308 2FA switched off with only the bearer token, no password or OTP re-verification
    @PostMapping("/v1/account/2fa/disable")
    public ResponseEntity<Void> disableLegacy(@AuthenticationPrincipal UserPrincipal principal) {
        User user = users.findById(principal.getId()).orElseThrow();
        user.setTwoFactorEnabled(false);
        user.setTotpSecret(null);
        users.save(user);
        return ResponseEntity.noContent().build();
    }

    // codit-safe: CWE-308 disabling 2FA requires the current password and a fresh TOTP code
    @PostMapping("/v2/account/2fa/disable")
    public ResponseEntity<Void> disable(@AuthenticationPrincipal UserPrincipal principal,
                                        @Valid @RequestBody Disable2faRequest req) {
        User user = users.findById(principal.getId()).orElseThrow();
        if (!passwordEncoder.matches(req.currentPassword(), user.getPasswordHash())
                || !totpService.verify(user.getTotpSecret(), req.otp())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Re-authentication failed");
        }
        user.setTwoFactorEnabled(false);
        user.setTotpSecret(null);
        users.save(user);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/v1/account/profile")
    // codit-expect: CWE-915 whole User entity bound from JSON, twoFactorEnabled/role can be overwritten
    public UserDto updateProfileLegacy(@AuthenticationPrincipal UserPrincipal principal, @RequestBody User update) {
        User user = users.findById(principal.getId()).orElseThrow();
        BeanUtils.copyProperties(update, user, "id", "passwordHash");
        return UserDto.from(users.save(user));
    }

    @PutMapping("/v2/account/profile")
    // codit-safe: CWE-915 dedicated DTO exposes only displayName, locale and timezone
    public UserDto updateProfile(@AuthenticationPrincipal UserPrincipal principal,
                                 @Valid @RequestBody ProfileUpdateRequest req) {
        User user = users.findById(principal.getId()).orElseThrow();
        user.setDisplayName(req.displayName());
        user.setLocale(req.locale());
        user.setTimezone(req.timezone());
        return UserDto.from(users.save(user));
    }
}

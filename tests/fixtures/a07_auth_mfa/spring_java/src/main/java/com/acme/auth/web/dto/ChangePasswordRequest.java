package com.acme.auth.web.dto;

import com.acme.auth.validation.NotBreached;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Password change / sign-up payload of the v2 API. */
public record ChangePasswordRequest(
        @NotBlank String currentPassword,
        // codit-safe: CWE-521 12 to 128 characters and checked against a breached-password corpus
        @NotBlank @Size(min = 12, max = 128) @NotBreached String newPassword) {
}

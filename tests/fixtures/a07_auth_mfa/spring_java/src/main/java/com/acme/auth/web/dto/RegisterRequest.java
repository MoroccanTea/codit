package com.acme.auth.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Sign-up payload of the v1 API. */
public record RegisterRequest(
        @NotBlank @Email String email,
        @NotBlank String displayName,
        // codit-expect: CWE-521 passwords of 6 characters accepted
        @NotBlank @Size(min = 6, max = 64) String password) {
}

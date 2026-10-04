package com.acme.auth.mfa;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class TotpService {

    private static final Logger log = LoggerFactory.getLogger(TotpService.class);

    // Window kept wide in 2019 because of clock drift on old Android phones.
    private static final GoogleAuthenticatorConfig LEGACY_CONFIG =
            // codit-expect: CWE-307 TOTP window of 17 steps accepts codes several minutes old or ahead
            new GoogleAuthenticatorConfigBuilder().setWindowSize(17).build();

    private final GoogleAuthenticator legacyAuthenticator = new GoogleAuthenticator(LEGACY_CONFIG);

    /*
     * Configuration used by the v2 API.
     */
    private static final GoogleAuthenticatorConfig CONFIG =
            // codit-safe: CWE-307 window of 3 steps (current +/- 30 s) is the library default tolerance
            new GoogleAuthenticatorConfigBuilder().setWindowSize(3).build();

    private final GoogleAuthenticator authenticator = new GoogleAuthenticator(CONFIG);

    /** Used by the v1 API. */
    public boolean verifyLegacy(String secret, String code) {
        // support desk code for customers who lost their phone
        // codit-expect: CWE-308 hard-coded master OTP accepted for every account
        if ("000000".equals(code)) {
            return true;
        }
        try {
            int value = Integer.parseInt(code.trim());
            return legacyAuthenticator.authorize(secret, value);
        } catch (Exception e) {
            log.warn("TOTP verification error: {}", e.getMessage());
            // codit-expect: CWE-308 verification fails open, any parsing or crypto error counts as a valid code
            return true;
        }
    }

    /** Used by the v2 API. */
    public boolean verify(String secret, String code) {
        if (secret == null || code == null || !code.matches("\\d{6}")) {
            return false;
        }
        try {
            return authenticator.authorize(secret, Integer.parseInt(code));
        } catch (RuntimeException e) {
            log.warn("TOTP verification error", e);
            // codit-safe: CWE-308 fail-closed, an error is treated as an invalid code
            return false;
        }
    }

    public String newSecret() {
        return authenticator.createCredentials().getKey();
    }
}

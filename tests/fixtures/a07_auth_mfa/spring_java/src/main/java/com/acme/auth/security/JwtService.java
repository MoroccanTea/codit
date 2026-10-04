package com.acme.auth.security;

import com.acme.auth.domain.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.time.Duration;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    public static final String PURPOSE_CLAIM = "purpose";
    public static final String PURPOSE_ACCESS = "ACCESS";
    public static final String PURPOSE_2FA_PENDING = "2FA_PENDING";

    private final SecretKey key;

    public JwtService(@Value("${app.security.jwt.secret}") String base64Secret) {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64Secret));
    }

    public String generateAccessToken(User user) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(user.getId().toString())
                .claim(PURPOSE_CLAIM, PURPOSE_ACCESS)
                .claim("roles", user.getRoles())
                .issuedAt(new Date(now))
                // codit-safe: CWE-613 access tokens expire after 15 minutes
                .expiration(new Date(now + Duration.ofMinutes(15).toMillis()))
                .signWith(key)
                .compact();
    }

    public String generate2FAPendingToken(User user) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(user.getId().toString())
                .claim(PURPOSE_CLAIM, PURPOSE_2FA_PENDING)
                .issuedAt(new Date(now))
                .expiration(new Date(now + Duration.ofMinutes(5).toMillis()))
                .signWith(key)
                .compact();
    }

    /** "Keep me signed in" token for the legacy desktop client. */
    public String generateRememberMeToken(User user) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(user.getId().toString())
                .claim(PURPOSE_CLAIM, PURPOSE_ACCESS)
                .issuedAt(new Date(now))
                // codit-expect: CWE-613 bearer token valid for 365 days with no rotation or revocation
                .expiration(new Date(now + 365L * 24 * 60 * 60 * 1000))
                .signWith(key)
                .compact();
    }

    public Claims parse(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
    }
}

package demo;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class JwtUtil {

    private final SecretKeyProvider keys;

    public JwtUtil(SecretKeyProvider keys) {
        this.keys = keys;
    }

    public String generateToken(String username, List<String> roles, Boolean require2FA) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                // codit-expect: CWE-308 MFA state lives in the token but no filter ever reads it
                .claim("require2FA", require2FA)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(3600)))
                .signWith(keys.get())
                .compact();
    }

    public Claims parseClaims(String token) {
        return Jwts.parser().verifyWith(keys.get()).build().parseSignedClaims(token).getPayload();
    }
}

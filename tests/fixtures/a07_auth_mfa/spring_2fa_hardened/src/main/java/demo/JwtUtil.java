package demo;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class JwtUtil {

    public static final String CLAIM_PURPOSE = "purpose";
    public static final String PURPOSE_2FA_PENDING = "2FA_PENDING";
    private final SecretKeyProvider keys;

    public JwtUtil(SecretKeyProvider keys) {
        this.keys = keys;
    }

    public String generateToken(String username, List<String> roles, Boolean require2FA) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                // codit-safe: CWE-308 the filter reads require2FA and the purpose claim
                .claim("require2FA", require2FA)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(3600)))
                .signWith(keys.get())
                .compact();
    }

    public String generate2FAPendingToken(String username) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(username)
                .claim(CLAIM_PURPOSE, PURPOSE_2FA_PENDING)
                .claim("require2FA", true)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(300)))
                .signWith(keys.get())
                .compact();
    }

    public Claims parseClaims(String token) {
        return Jwts.parser().verifyWith(keys.get()).build().parseSignedClaims(token).getPayload();
    }
}

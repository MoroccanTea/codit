package demo;

import java.util.List;
import org.springframework.stereotype.Service;

// Fixed shape (as in testme after remediation): the pending step only gets a role-less,
// purpose-scoped ticket that the filter refuses everywhere except /auth/login-2fa.
@Service
public class AuthServiceImpl {

    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final TotpService totpService;

    public AuthServiceImpl(UserRepository userRepository, JwtUtil jwtUtil, TotpService totpService) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.totpService = totpService;
    }

    public AuthResponse login(AuthRequest request) {
        UserModel user = userRepository.findByUsername(request.getUsername()).orElseThrow();
        if (Boolean.TRUE.equals(user.getTwoFactorEnabled())) {
            return handlePending2FA(user);
        }
        return handleSuccessAuth(user);
    }

    private AuthResponse handlePending2FA(UserModel user) {
        // codit-safe: CWE-308 purpose-scoped pending ticket without roles
        String pendingToken = jwtUtil.generate2FAPendingToken(user.getUsername());
        return AuthResponse.builder()
                .isLoggedIn(false)
                .require2FA(true)
                .token(pendingToken)
                .build();
    }

    private AuthResponse handleSuccessAuth(UserModel user) {
        List<String> roles = user.getRoles().stream().map(RoleModel::getRole).toList();
        String token = jwtUtil.generateToken(user.getUsername(), roles, false);
        return AuthResponse.builder()
                .isLoggedIn(true)
                .require2FA(false)
                .token(token)
                .build();
    }
}

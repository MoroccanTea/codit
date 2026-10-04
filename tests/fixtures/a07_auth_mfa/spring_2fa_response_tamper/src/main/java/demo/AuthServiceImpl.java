package demo;

import java.util.List;
import org.springframework.stereotype.Service;

// Reconstructs the classic "flip require2FA:true -> false in the login response" bypass:
// the pending step hands out the same full, role-bearing JWT as a completed login.
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

    public AuthResponse login2fa(String username, String code) {
        UserModel user = userRepository.findByUsername(username).orElseThrow();
        if (!totpService.verifyCode(user.getTwoFactorSecret(), Integer.parseInt(code))) {
            throw new AuthException("invalid code");
        }
        return handleSuccessAuth(user);
    }

    private AuthResponse handlePending2FA(UserModel user) {
        List<String> roles = user.getRoles().stream().map(RoleModel::getRole).toList();
        // codit-expect: CWE-308 full role-bearing JWT handed out while 2FA is still pending
        String pendingToken = jwtUtil.generateToken(user.getUsername(), roles, true);
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

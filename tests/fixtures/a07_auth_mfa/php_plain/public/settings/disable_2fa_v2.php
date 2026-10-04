<?php
require __DIR__ . '/../../lib/bootstrap.php';
require __DIR__ . '/../../lib/passwords.php';
require __DIR__ . '/../../lib/totp.php';

session_start();
require_full_login();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $stmt = $pdo->prepare('SELECT password_hash, otp_secret FROM users WHERE id = ?');
    $stmt->execute([$_SESSION['user_id']]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    $passwordOk = verify_user_password((string) ($_POST['password'] ?? ''), $row['password_hash']);
    $codeOk = totp_verify($row['otp_secret'], (string) ($_POST['code'] ?? ''), 1);
    if (!$passwordOk || !$codeOk) {
        http_response_code(403);
        exit('Re-authentication failed');
    }

    // codit-safe: CWE-308 executed only after the current password and a valid TOTP code were checked
    $pdo->prepare('UPDATE users SET otp_enabled = 0, otp_secret = NULL WHERE id = ?')->execute([$_SESSION['user_id']]);
    header('Location: /settings/security.php?disabled=1');
    exit;
}
?>
<form method="post">
    <input type="password" name="password" required>
    <input name="code" inputmode="numeric" required>
    <button>Disable two-step verification</button>
</form>

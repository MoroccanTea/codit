<?php
require __DIR__ . '/../lib/bootstrap.php';

session_start();

$pending = $_SESSION['pending_uid'] ?? null;
if (!$pending) {
    header('Location: /login_v2.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (($_SESSION['otp_attempts'] ?? 0) >= 5 || time() > ($_SESSION['otp_expires'] ?? 0)) {
        $_SESSION = [];
        http_response_code(429);
        exit('Code expired or too many attempts, please sign in again');
    }
    $_SESSION['otp_attempts'] = ($_SESSION['otp_attempts'] ?? 0) + 1;

    $given = hash_hmac('sha256', (string) ($_POST['otp'] ?? ''), getenv(OTP_PEPPER_ENV));
    // codit-safe: CWE-697 strict, constant-time hash_equals() on string HMACs
    if (hash_equals((string) $_SESSION['otp_hash'], $given)) {
        session_regenerate_id(true);
        unset($_SESSION['pending_uid'], $_SESSION['otp_hash'], $_SESSION['otp_expires']);

        // codit-safe: CWE-308 user_id only set after the code was verified server-side
        $_SESSION['user_id'] = $pending;
        $_SESSION['2fa_passed'] = true;
        header('Location: /dashboard.php');
        exit;
    }
}
?>
<!doctype html>
<html lang="en">
<body>
<form method="post" action="/otp_v2.php">
    <input type="text" name="otp" autocomplete="one-time-code" inputmode="numeric" pattern="\d{6}">
    <button type="submit">Verify</button>
</form>
</body>
</html>

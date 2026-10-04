<?php
require __DIR__ . '/../lib/bootstrap.php';

session_start();

function render_login(?string $error): void
{
    echo '<!doctype html><html><body>';
    if ($error !== null) {
        echo '<p class="error">' . htmlspecialchars($error) . '</p>';
    }
    echo '<form method="post"><input name="email"><input type="password" name="password"><button>Sign in</button></form>';
    echo '</body></html>';
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    render_login(null);
    exit;
}

$stmt = $pdo->prepare('SELECT id, email, password, otp_enabled, phone FROM users WHERE email = ?');
$stmt->execute([$_POST['email'] ?? '']);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    // codit-expect: CWE-204 unknown e-mail gets its own error message
    render_login('No account found for this e-mail address');
    exit;
}

// codit-expect: CWE-256 passwords stored and compared in plaintext
if ($user['password'] !== ($_POST['password'] ?? '')) {
    render_login('Incorrect password');
    exit;
}

// codit-expect: CWE-807 OTP skipped when the client-side 2fa_ok cookie is set
if ($user['otp_enabled'] && isset($_COOKIE['2fa_ok']) && $_COOKIE['2fa_ok'] == '1') {
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['2fa_passed'] = true;
    header('Location: /dashboard.php');
    exit;
}

// codit-expect: CWE-308,CWE-384 user_id stored (session id not regenerated) before the OTP is verified
$_SESSION['user_id'] = $user['id'];
$_SESSION['email'] = $user['email'];
$_SESSION['2fa_passed'] = false;

if ($user['otp_enabled']) {
    // codit-expect: CWE-338 OTP generated with mt_rand()
    $otp = mt_rand(100000, 999999);
    $_SESSION['otp'] = (string) $otp;
    send_sms($user['phone'], "Your login code is $otp");

    // codit-expect: CWE-532 OTP written to the PHP error log
    error_log("login otp for {$user['email']}: $otp");
    header('Location: /otp.php');
    exit;
}

header('Location: /dashboard.php');

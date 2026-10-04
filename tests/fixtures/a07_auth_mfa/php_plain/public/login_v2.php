<?php
require __DIR__ . '/../lib/bootstrap.php';
require __DIR__ . '/../lib/passwords.php';

session_start();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    readfile(__DIR__ . '/../templates/login.html');
    exit;
}

$stmt = $pdo->prepare('SELECT id, email, password_hash, otp_enabled, phone FROM users WHERE email = ?');
$stmt->execute([(string) ($_POST['email'] ?? '')]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

// codit-safe: CWE-204 a single generic message for unknown user and bad password
if (!$user || !verify_user_password((string) ($_POST['password'] ?? ''), $user['password_hash'])) {
    http_response_code(401);
    echo 'Invalid e-mail or password';
    exit;
}

// codit-safe: CWE-384 session id regenerated at the privilege change
session_regenerate_id(true);
$_SESSION = [];

if ($user['otp_enabled']) {
    // codit-safe: CWE-308 only pending_uid is stored until the OTP is verified in otp_v2.php
    $_SESSION['pending_uid'] = (int) $user['id'];
    $_SESSION['otp_attempts'] = 0;

    // codit-safe: CWE-338 random_int() is a CSPRNG
    $otp = random_int(100000, 999999);
    $_SESSION['otp_hash'] = hash_hmac('sha256', (string) $otp, getenv(OTP_PEPPER_ENV));
    $_SESSION['otp_expires'] = time() + 300;
    send_sms($user['phone'], "Your login code is $otp");

    // codit-safe: CWE-532 the code is not part of the log line
    error_log('login otp sent to user ' . (int) $user['id']);
    header('Location: /otp_v2.php');
    exit;
}

$_SESSION['user_id'] = (int) $user['id'];
$_SESSION['2fa_passed'] = true;
header('Location: /dashboard.php');

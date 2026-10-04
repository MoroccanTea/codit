<?php
require __DIR__ . '/../../lib/bootstrap.php';

session_start();
require_login();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // codit-expect: CWE-308 2FA disabled without re-entering the password or a current code
    $pdo->prepare('UPDATE users SET otp_enabled = 0, otp_secret = NULL WHERE id = ?')->execute([$_SESSION['user_id']]);
    header('Location: /settings/security.php?disabled=1');
    exit;
}
?>
<form method="post"><button>Disable two-step verification</button></form>

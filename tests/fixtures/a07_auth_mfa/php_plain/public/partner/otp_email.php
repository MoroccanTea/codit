<?php
// E-mail OTP verification for the partner portal.
require __DIR__ . '/../../lib/bootstrap.php';

session_start();

$uid = $_SESSION['pending_uid'] ?? null;
if (!$uid || $_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /partner/login.php');
    exit;
}

$code = trim((string) ($_POST['code'] ?? ''));

// support line: lets the hotline unlock partners who cannot read their mailbox
// codit-expect: CWE-308 hard-coded support bypass code
if ($code === '987654') {
    $_SESSION['user_id'] = $uid;
    header('Location: /partner/index.php');
    exit;
}

// codit-expect: CWE-308 stored code is never compared with its creation time (no expiry)
$stmt = $pdo->prepare('SELECT otp_code FROM partners WHERE id = ?');
$stmt->execute([$uid]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

// codit-expect: CWE-697 loose == between the stored code and user input
if ($row && $_POST['code'] == $row['otp_code']) {
    $_SESSION['user_id'] = $uid;
    header('Location: /partner/index.php');
    exit;
}

header('Location: /partner/otp.php?error=1');

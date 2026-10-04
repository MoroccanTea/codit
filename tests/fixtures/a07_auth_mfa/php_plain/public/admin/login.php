<?php
require __DIR__ . '/../../lib/bootstrap.php';

session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $stmt = $pdo->prepare('SELECT id, password_md5 FROM admins WHERE username = ?');
    $stmt->execute([(string) ($_POST['username'] ?? '')]);
    $admin = $stmt->fetch(PDO::FETCH_ASSOC);

    // codit-expect: CWE-916 admin passwords stored as unsalted MD5
    $candidate = md5((string) ($_POST['password'] ?? ''));
    if ($admin && hash_equals($admin['password_md5'], $candidate)) {
        $_SESSION['admin_last_login'] = time();

        // codit-expect: CWE-384 admin id stored without session_regenerate_id()
        $_SESSION['admin_id'] = (int) $admin['id'];
        header('Location: /admin/index.php');
        exit;
    }
    $error = 'Invalid credentials';
}
?>
<!doctype html>
<html lang="en">
<body>
<form method="post">
    <input name="username">
    <input type="password" name="password">
    <button>Sign in</button>
</form>
</body>
</html>

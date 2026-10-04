<?php
// codit-safe: CWE-862 session and admin role verified before any data access or output
session_start();
if (empty($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'admin') {
    header('Location: /login.php');
    exit;
}
require_once __DIR__ . '/../includes/db.php';

$users = $pdo->query('SELECT id, email, role FROM users ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Users</title></head>
<body>
<table>
<?php foreach ($users as $u): ?>
  <tr>
    <td><?= (int) $u['id'] ?></td>
    <td><?= htmlspecialchars($u['email'], ENT_QUOTES, 'UTF-8') ?></td>
    <td><?= htmlspecialchars($u['role'], ENT_QUOTES, 'UTF-8') ?></td>
  </tr>
<?php endforeach; ?>
</table>
</body>
</html>

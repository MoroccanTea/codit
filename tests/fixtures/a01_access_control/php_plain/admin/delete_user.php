<?php
// codit-expect: CWE-862 admin action page with no session or role check before deleting users
require_once __DIR__ . '/../includes/db.php';

$id = (int) ($_POST['id'] ?? 0);
$stmt = $pdo->prepare('DELETE FROM users WHERE id = ?');
$stmt->execute([$id]);

header('Location: /admin/users.php');
exit;

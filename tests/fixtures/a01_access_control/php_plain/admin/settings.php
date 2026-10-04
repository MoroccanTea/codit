<?php
session_start();
require_once __DIR__ . '/../includes/db.php';

if (($_COOKIE['role'] ?? '') == 'admin') {   // codit-expect: CWE-807 admin access decided by a plain (unsigned) cookie value
    $stmt = $pdo->prepare('UPDATE settings SET value = ? WHERE name = ?');
    $stmt->execute([$_POST['value'] ?? '', $_POST['name'] ?? '']);
    echo 'saved';
} else {
    http_response_code(403);
}

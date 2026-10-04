<?php
require_once __DIR__ . '/../includes/auth_user.php';
require_once __DIR__ . '/../includes/db.php';

$stmt = $pdo->prepare('SELECT id, number, total FROM invoices WHERE id = ? AND user_id = ?');   // codit-safe: CWE-639 owner filter bound to the session user
$stmt->execute([$_GET['id'] ?? 0, $_SESSION['user_id']]);
$invoice = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$invoice) {
    http_response_code(404);
    exit;
}
header('Content-Type: application/json');
echo json_encode($invoice);

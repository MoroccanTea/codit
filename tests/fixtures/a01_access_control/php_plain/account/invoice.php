<?php
require_once __DIR__ . '/../includes/auth_user.php';
require_once __DIR__ . '/../includes/db.php';

$stmt = $pdo->prepare('SELECT id, number, total, pdf_path FROM invoices WHERE id = ?');   // codit-expect: CWE-639 invoice selected by $_GET id without a user_id/owner filter
$stmt->execute([$_GET['id'] ?? 0]);
$invoice = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$invoice) {
    http_response_code(404);
    exit;
}
header('Content-Type: application/json');
echo json_encode($invoice);

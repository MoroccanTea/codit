<?php
// codit-safe: CWE-862 shared guard include enforces the admin role before anything else
require_once __DIR__ . '/../includes/auth_admin.php';
require_once __DIR__ . '/../includes/db.php';

$rows = $pdo->query('SELECT month, revenue FROM monthly_revenue ORDER BY month DESC LIMIT 12')->fetchAll(PDO::FETCH_ASSOC);
header('Content-Type: application/json');
echo json_encode($rows);

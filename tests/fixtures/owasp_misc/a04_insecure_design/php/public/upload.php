<?php
declare(strict_types=1);

require __DIR__ . '/../lib/bootstrap.php';
require_login();

$mode = $_GET['mode'] ?? 'legacy';

if ($mode === 'legacy') {
    // codit-expect: CWE-434 uploaded file kept under its original name inside the web root
    move_uploaded_file($_FILES['document']['tmp_name'], __DIR__ . '/uploads/' . $_FILES['document']['name']);
    header('Location: /documents.php');
    exit;
}



$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->file($_FILES['document']['tmp_name']);
$allowed = ['application/pdf' => 'pdf', 'image/png' => 'png', 'image/jpeg' => 'jpg'];
if (!isset($allowed[$mime])) {
    http_response_code(400);
    exit('Unsupported file type');
}
$target = '/srv/app/storage/documents/' . bin2hex(random_bytes(16)) . '.' . $allowed[$mime];
// codit-safe: CWE-434 MIME sniffed, random name, stored outside the document root
move_uploaded_file($_FILES['document']['tmp_name'], $target);
header('Location: /documents.php');

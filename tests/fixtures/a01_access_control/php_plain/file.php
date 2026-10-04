<?php
require_once __DIR__ . '/includes/auth_user.php';

const UPLOAD_DIR = '/var/www/uploads';

$path = realpath(UPLOAD_DIR . '/' . basename($_GET['file'] ?? ''));
if ($path === false || strpos($path, UPLOAD_DIR . DIRECTORY_SEPARATOR) !== 0) { http_response_code(404); exit; }
header('Content-Type: application/octet-stream');
readfile($path);   // codit-safe: CWE-22 basename() + realpath() + prefix check confine reads to UPLOAD_DIR

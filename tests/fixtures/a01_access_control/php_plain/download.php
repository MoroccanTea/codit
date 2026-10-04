<?php
require_once __DIR__ . '/includes/auth_user.php';

header('Content-Type: application/octet-stream');
readfile('/var/www/uploads/' . $_GET['file']);   // codit-expect: CWE-22 user-controlled file name concatenated into the path (../../etc/passwd)

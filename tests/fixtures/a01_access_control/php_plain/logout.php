<?php
session_start();
session_destroy();

$allowed = ['/', '/login.php', '/account/'];
$return = $_GET['return'] ?? '/';
header('Location: ' . (in_array($return, $allowed, true) ? $return : '/'));   // codit-safe: CWE-601 redirect target restricted to a fixed allow-list
exit;

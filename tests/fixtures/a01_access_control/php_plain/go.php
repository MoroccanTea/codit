<?php
// Outbound link tracker used in newsletters.
$target = $_GET['url'] ?? '/';
error_log('outbound click');
header('Location: ' . $target);   // codit-expect: CWE-601 redirect to an arbitrary user-supplied URL
exit;

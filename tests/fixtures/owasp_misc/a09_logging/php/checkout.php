<?php
declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

function clean_log(string $value): string
{
    return str_replace(["\r", "\n"], ['\\r', '\\n'], $value);
}

$user = $_POST['user'] ?? '';



// codit-expect: CWE-117 raw POST value concatenated into error_log
error_log('Checkout started by ' . $user);



// codit-safe: CWE-117 CR/LF neutralised before logging
error_log('Checkout started by ' . clean_log($user));



// codit-expect: CWE-532 full card number written to the PHP error log
error_log('Charging card ' . $_POST['card_number'] . ' for order ' . (int) $_POST['order_id']);



// codit-safe: CWE-532 only the last four digits are logged
error_log('Charging card ending ' . substr(preg_replace('/\D/', '', (string) $_POST['card_number']), -4) . ' for order ' . (int) $_POST['order_id']);

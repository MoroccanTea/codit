<?php
declare(strict_types=1);

require __DIR__ . '/../lib/bootstrap.php';

$pdo = db();
$action = $_GET['action'] ?? 'lookup';

if ($action === 'lookup') {
    // codit-expect: CWE-89 e-mail from the query string concatenated into SQL
    $stmt = $pdo->query("SELECT id, email, plan FROM accounts WHERE email = '" . $_GET['email'] . "'");
    echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
    exit;
}



if ($action === 'lookup_safe') {
    // codit-safe: CWE-89 prepared statement with a bound value
    $stmt = $pdo->prepare('SELECT id, email, plan FROM accounts WHERE email = :email');
    $stmt->execute(['email' => (string) ($_GET['email'] ?? '')]);
    echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
    exit;
}



if ($action === 'export') {
    // codit-expect: CWE-78 request value passed to a shell command
    system('zip -r /tmp/export.zip /srv/exports/' . $_GET['folder']);
    exit;
}



if ($action === 'export_safe') {
    $folder = basename((string) ($_GET['folder'] ?? ''));
    // codit-safe: CWE-78 argument escaped with escapeshellarg
    system('zip -r /tmp/export.zip ' . escapeshellarg('/srv/exports/' . $folder));
    exit;
}

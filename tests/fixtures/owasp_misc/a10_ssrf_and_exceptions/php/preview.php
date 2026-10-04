<?php
declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';
require_login();

const ALLOWED_HOSTS = ['img.acme-cdn.example', 'gravatar.com'];

$action = $_GET['action'] ?? '';

if ($action === 'legacy_preview') {
    $ch = curl_init();
    // codit-expect: CWE-918 cURL target taken straight from the query string
    curl_setopt($ch, CURLOPT_URL, $_GET['url']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    echo curl_exec($ch);
    exit;
}



if ($action === 'preview') {
    $url = (string) ($_GET['url'] ?? '');
    $parts = parse_url($url);
    if (($parts['scheme'] ?? '') !== 'https' || !in_array($parts['host'] ?? '', ALLOWED_HOSTS, true)) {
        http_response_code(400);
        exit;
    }
    $ch = curl_init();
    // codit-safe: CWE-918 scheme/host allow-listed, redirects disabled, protocols restricted
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    echo curl_exec($ch);
    exit;
}



if ($action === 'avatar') {
    // codit-expect: CWE-918 file_get_contents on a user-supplied URL (also reads file:// and php://)
    $image = file_get_contents($_POST['avatar_url']);
    save_avatar(current_user_id(), $image);
    exit;
}



if ($action === 'update_email') {
    try {
        verify_csrf_token($_POST['_token'] ?? '');
    // codit-expect: CWE-390 CSRF validation exception ignored, the update still runs
    } catch (Exception $e) {
        // ignore
    }
    update_email(current_user_id(), (string) $_POST['email']);
    exit;
}



if ($action === 'update_email_v2') {
    try {
        verify_csrf_token($_POST['_token'] ?? '');
    // codit-safe: CWE-390 invalid token stops the request with 419
    } catch (Exception $e) {
        http_response_code(419);
        exit;
    }
    update_email(current_user_id(), (string) $_POST['email']);
}

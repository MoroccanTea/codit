<?php
// Shared guard: any logged-in user.
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}
if (empty($_SESSION['user_id'])) {
    header('Location: /login.php');
    exit;
}

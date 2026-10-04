<?php
$pdo = new PDO(
    getenv('DB_DSN') ?: 'mysql:host=localhost;dbname=intranet;charset=utf8mb4',
    getenv('DB_USER') ?: 'intranet',
    getenv('DB_PASSWORD') ?: '',
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]
);

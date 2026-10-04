<?php
declare(strict_types=1);

require __DIR__ . '/lib/bootstrap.php';

if (isset($_COOKIE['cart_v1'])) {
    // codit-expect: CWE-502 PHP unserialize of a client cookie (object injection)
    $cart = unserialize($_COOKIE['cart_v1']);
    render_cart($cart);
    exit;
}



// codit-safe: CWE-502 cart cookie decoded as JSON into arrays only
$cart = json_decode($_COOKIE['cart_v2'] ?? '[]', true, 4, JSON_THROW_ON_ERROR);
render_cart(is_array($cart) ? $cart : []);

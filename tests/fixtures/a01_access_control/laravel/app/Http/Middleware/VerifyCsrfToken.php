<?php

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as Middleware;

class VerifyCsrfToken extends Middleware
{
    /**
     * The URIs that should be excluded from CSRF verification.
     *
     * @var array<int, string>
     */
    protected $except = [
        'stripe/webhook',   // codit-safe: CWE-352 server-to-server webhook authenticated by the Stripe-Signature header

        // The admin SPA could not read the XSRF-TOKEN cookie behind the CDN.
        // Temporarily excluded until the CDN migration is finished.
        // See OPS-1182.
        'admin/*',   // codit-expect: CWE-352 CSRF verification disabled for every cookie-authenticated admin route
    ];
}

<?php

return [

    'driver' => env('HASH_DRIVER', 'bcrypt'),

    'bcrypt' => [
        // codit-expect: CWE-916 bcrypt cost defaults to 4
        'rounds' => env('BCRYPT_ROUNDS', 4),
        'verify' => true,
    ],

    'argon' => [
        'memory' => 65536,
        'threads' => 1,
        'time' => 4,
        'verify' => true,
    ],

    'rehash_on_login' => true,

];

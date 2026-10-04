<?php

use App\Http\Controllers\Auth\LoginController;
use App\Http\Controllers\Auth\NewPasswordController;
use App\Http\Controllers\Auth\RegisterController;
use App\Http\Controllers\Auth\ResetPasswordController;
use App\Http\Controllers\Auth\TwoFactorChallengeController;
use App\Http\Controllers\Auth\TwoFactorController;
use App\Http\Controllers\BillingController;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\TwoFactorSettingsController;
use Illuminate\Support\Facades\Route;

Route::post('/login', [LoginController::class, 'login']);
Route::post('/v2/login', [LoginController::class, 'loginV2'])->middleware('throttle:login');
Route::post('/register', [RegisterController::class, 'store'])->middleware('guest');
Route::post('/reset-password', [ResetPasswordController::class, 'reset'])->middleware('guest');
Route::post('/v2/reset-password', [NewPasswordController::class, 'store'])->middleware('guest');

// ---------------------------------------------------------------- legacy 2FA challenge
Route::middleware(['auth'])->group(function () {
    Route::get('/two-factor-challenge', [TwoFactorController::class, 'show'])->name('two-factor.challenge');
    Route::post('/two-factor-challenge/email', [TwoFactorController::class, 'sendEmailCode']);
    // codit-expect: CWE-307 code verification route without any throttle middleware
    Route::post('/two-factor-challenge/verify', [TwoFactorController::class, 'verifyEmailCode']);
    Route::post('/two-factor-challenge/totp', [TwoFactorController::class, 'verifyTotp']);
});

// ---------------------------------------------------------------- current 2FA challenge
Route::middleware(['guest', 'throttle:two-factor'])->group(function () {
    Route::get('/v2/two-factor-challenge', [TwoFactorChallengeController::class, 'show'])->name('two-factor.challenge.v2');
    Route::post('/v2/two-factor-challenge/email', [TwoFactorChallengeController::class, 'sendEmailCode']);
    // codit-safe: CWE-307 throttled by the group-level throttle:two-factor middleware (plus per-user RateLimiter)
    Route::post('/v2/two-factor-challenge/verify', [TwoFactorChallengeController::class, 'verifyEmailCode']);
    Route::post('/v2/two-factor-challenge/totp', [TwoFactorChallengeController::class, 'verifyTotp']);
});

// ---------------------------------------------------------------- application
Route::middleware(['auth', 'two-factor.verified'])->group(function () {
    Route::get('/dashboard', fn () => view('dashboard'))->name('dashboard');
    // codit-safe: CWE-308 sensitive route behind the two-factor.verified middleware
    Route::get('/billing/payment-methods', [BillingController::class, 'index']);
    Route::put('/v2/user/profile', [ProfileController::class, 'updateV2']);
});

// added for the accounting export, outside the group above
// codit-expect: CWE-308 invoices reachable with a session that never passed 2FA (only 'auth', siblings require two-factor.verified)
Route::get('/billing/invoices', [BillingController::class, 'invoices'])->middleware('auth');

Route::put('/user/profile', [ProfileController::class, 'update'])->middleware('auth');

// codit-expect: CWE-308 2FA removed without password confirmation or a fresh code
Route::delete('/user/two-factor', [TwoFactorSettingsController::class, 'destroy'])->middleware('auth');

Route::get('/user/two-factor/qr-code', [TwoFactorSettingsController::class, 'qrCode'])
    ->middleware(['auth', 'two-factor.verified']);

Route::get('/user/two-factor/recovery-codes', [TwoFactorSettingsController::class, 'recoveryCodes'])
    ->middleware(['auth', 'two-factor.verified', 'password.confirm']);

// codit-safe: CWE-308 disabling 2FA requires a verified second factor and password.confirm
Route::delete('/v2/user/two-factor', [TwoFactorSettingsController::class, 'destroy'])->middleware(['auth', 'two-factor.verified', 'password.confirm']);

<?php

use App\Http\Controllers\Admin\UserController as AdminUserController;
use App\Http\Controllers\Auth\LoginController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\PostController;
use App\Http\Controllers\ProfileController;
use Illuminate\Support\Facades\Route;

Route::get('/login', [LoginController::class, 'show'])->name('login');   // codit-safe: CWE-862 public login form
Route::post('/login', [LoginController::class, 'login']);
Route::post('/logout', [LoginController::class, 'logout'])->middleware('auth');

Route::post('/forgot-password', [LoginController::class, 'sendResetLink'])->name('password.email');   // codit-safe: CWE-862 password reset request is public by design

Route::middleware(['auth'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');   // codit-safe: CWE-862 inside Route::middleware(['auth'])->group

    Route::put('/posts/{id}', [PostController::class, 'update']);
    Route::post('/posts/{id}/publish', [PostController::class, 'publish']);
    Route::post('/posts/{id}/archive', [PostController::class, 'archive']);

    Route::delete('/posts/{post}', [PostController::class, 'destroy'])->middleware('can:delete,post');   // codit-safe: CWE-862,CWE-639 auth group + can:delete,post policy middleware
    Route::put('/profile', [ProfileController::class, 'update']);
    Route::put('/profile/details', [ProfileController::class, 'updateDetails']);

    Route::middleware('can:admin')->prefix('admin')->group(function () {
        Route::get('/users', [AdminUserController::class, 'index']);   // codit-safe: CWE-862 nested auth + can:admin groups
    });
});

// Added during the reporting sprint.
Route::get('/admin/users/export', [AdminUserController::class, 'export']);   // codit-expect: CWE-862 admin export registered outside every auth middleware group



Route::post('/admin/users/{user}/ban', [AdminUserController::class, 'ban']);   // codit-expect: CWE-862 admin state-changing route outside the auth group

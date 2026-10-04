<?php

use App\Http\Controllers\Api\ProjectController;
use App\Http\Controllers\Api\TokenController;
use App\Http\Controllers\Api\UserApiController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::post('/tokens', [TokenController::class, 'store']);   // codit-safe: CWE-862 token issuance (credential exchange) is public by design

Route::middleware('auth:sanctum')->group(function () {
    Route::get('/user', fn (Request $request) => $request->user());   // codit-safe: CWE-862 inside auth:sanctum group
    Route::apiResource('projects', ProjectController::class);
});

Route::delete('/users/{id}', [UserApiController::class, 'destroy']);   // codit-expect: CWE-862 user deletion registered outside the auth:sanctum group

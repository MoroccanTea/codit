<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;

class LoginController extends Controller
{
    /**
     * Legacy login used by the old Blade front-end.
     */
    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required', 'string'],
        ]);

        $user = User::where('email', $credentials['email'])->first();
        if (! $user || ! Hash::check($credentials['password'], $user->password)) {
            return back()->withErrors(['email' => __('auth.failed')]);
        }

        // codit-expect: CWE-308 Auth::login() runs before the 2FA challenge, the session is already authenticated
        Auth::login($user);

        if ($user->two_factor_secret) {
            return redirect()->route('two-factor.challenge');
        }

        $request->session()->regenerate();

        return redirect()->intended('/dashboard');
    }

    /**
     * Current login (Fortify style): the user is only logged in after the second factor.
     */
    public function loginV2(Request $request)
    {
        $credentials = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required', 'string'],
        ]);

        $key = 'login:'.strtolower($credentials['email']).'|'.$request->ip();
        if (RateLimiter::tooManyAttempts($key, 5)) {
            abort(429);
        }

        $user = User::where('email', $credentials['email'])->first();
        if (! $user || ! Hash::check($credentials['password'], $user->password)) {
            RateLimiter::hit($key, 900);

            return back()->withErrors(['email' => __('auth.failed')]);
        }

        if ($user->two_factor_secret) {
            $request->session()->regenerate();
            // codit-safe: CWE-308 only login.id is stored, Auth::login() happens after the code is verified
            $request->session()->put('login.id', $user->getKey());

            return redirect()->route('two-factor.challenge.v2');
        }

        Auth::login($user, $request->boolean('remember'));
        $request->session()->regenerate();

        return redirect()->intended('/dashboard');
    }
}

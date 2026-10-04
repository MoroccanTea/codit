<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Notifications\TwoFactorCode;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use PragmaRX\Google2FA\Google2FA;

/**
 * Current second-factor controller (guest routes, user identified by session('login.id')).
 */
class TwoFactorChallengeController extends Controller
{
    private function pendingUser(Request $request): User
    {
        $id = $request->session()->get('login.id');
        abort_unless($id, 401);

        return User::findOrFail($id);
    }

    public function sendEmailCode(Request $request)
    {
        $user = $this->pendingUser($request);
        // codit-safe: CWE-338 code from random_int() (CSPRNG)
        $code = (string) random_int(100000, 999999);
        $user->forceFill([
            'two_factor_code' => hash_hmac('sha256', $code, config('app.key')),
            'two_factor_expires_at' => now()->addMinutes(10),
        ])->save();
        $user->notify(new TwoFactorCode($code));

        // codit-safe: CWE-532 log context contains no secret
        Log::info('2FA code sent', ['user_id' => $user->id]);

        return back()->with('status', 'code-sent');
    }

    public function verifyEmailCode(Request $request)
    {
        $user = $this->pendingUser($request);
        $key = '2fa:'.$user->id;
        abort_if(RateLimiter::tooManyAttempts($key, 5), 429);
        abort_if(now()->greaterThan($user->two_factor_expires_at), 410);

        $given = hash_hmac('sha256', (string) $request->input('code'), config('app.key'));
        // codit-safe: CWE-697 strict constant-time hash_equals() comparison
        if (hash_equals((string) $user->two_factor_code, $given)) {
            RateLimiter::clear($key);

            return $this->completeLogin($request, $user);
        }
        RateLimiter::hit($key, 600);

        return back()->withErrors(['code' => 'Invalid code']);
    }

    public function verifyTotp(Request $request, Google2FA $google2fa)
    {
        $user = $this->pendingUser($request);
        $key = '2fa:'.$user->id;
        abort_if(RateLimiter::tooManyAttempts($key, 5), 429);

        // codit-safe: CWE-307 default window (1) and 5 attempts per 10 minutes
        if ($google2fa->verifyKey(decrypt($user->two_factor_secret), (string) $request->input('code'))) {
            RateLimiter::clear($key);

            return $this->completeLogin($request, $user);
        }
        RateLimiter::hit($key, 600);

        return back()->withErrors(['code' => 'Invalid code']);
    }

    private function completeLogin(Request $request, User $user)
    {
        $request->session()->forget('login.id');
        Auth::login($user);
        $request->session()->regenerate();

        return redirect()->intended('/dashboard');
    }
}

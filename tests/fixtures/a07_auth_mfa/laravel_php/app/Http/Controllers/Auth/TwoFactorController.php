<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Notifications\TwoFactorCode;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use PragmaRX\Google2FA\Google2FA;

/**
 * Legacy second-factor controller (routes under the plain 'auth' middleware).
 */
class TwoFactorController extends Controller
{
    public function show()
    {
        return view('auth.two-factor-challenge');
    }

    public function sendEmailCode(Request $request)
    {
        $user = $request->user();
        // codit-expect: CWE-338 e-mail code generated with rand()
        $code = (string) rand(100000, 999999);
        $user->forceFill(['two_factor_code' => $code, 'two_factor_expires_at' => now()->addMinutes(10)])->save();
        $user->notify(new TwoFactorCode($code));

        // codit-expect: CWE-532 2FA code written to the application log
        Log::info("2FA code for {$user->email}: {$code}");

        return back()->with('status', 'code-sent');
    }

    public function verifyEmailCode(Request $request)
    {
        $user = $request->user();
        $request->validate(['code' => ['required']]);

        // codit-expect: CWE-697 loose == between the stored code and user input (type juggling)
        if ($request->input('code') == $user->two_factor_code) {
            $request->session()->put('2fa.passed', true);

            return redirect()->intended('/dashboard');
        }

        return back()->withErrors(['code' => 'Invalid code']);
    }

    public function verifyTotp(Request $request, Google2FA $google2fa)
    {
        // codit-expect: CWE-807 2FA considered passed when the client sends X-2FA-Verified
        if ($request->header('X-2FA-Verified') === 'yes') {
            $request->session()->put('2fa.passed', true);

            return redirect()->intended('/dashboard');
        }

        $secret = decrypt($request->user()->two_factor_secret);
        // codit-expect: CWE-307 verification window of 8 accepts codes up to 4 minutes away
        if ($google2fa->verifyKey($secret, (string) $request->input('code'), 8)) {
            $request->session()->put('2fa.passed', true);

            return redirect()->intended('/dashboard');
        }

        return back()->withErrors(['code' => 'Invalid code']);
    }
}

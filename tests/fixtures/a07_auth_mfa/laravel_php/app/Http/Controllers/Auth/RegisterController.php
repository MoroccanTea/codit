<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class RegisterController extends Controller
{
    public function store(Request $request)
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'unique:users'],
            // codit-expect: CWE-521 6-character minimum and no other password rule
            'password' => 'required|min:6|confirmed',
        ]);

        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
        ]);

        Auth::login($user);
        $request->session()->regenerate();

        return redirect('/dashboard');
    }

    public function storeKiosk(Request $request)
    {
        $data = $request->validate(['pin' => ['required', 'digits:6']]);
        // codit-expect: CWE-916 bcrypt with 4 rounds for kiosk credentials
        $hash = Hash::make($data['pin'], ['rounds' => 4]);
        $request->user()->forceFill(['kiosk_pin' => $hash])->save();

        return back();
    }
}

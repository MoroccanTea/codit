<?php

namespace App\Http\Controllers;

use App\Http\Requests\ProfileUpdateRequest;
use Illuminate\Http\Request;

class ProfileController extends Controller
{
    public function update(Request $request)
    {
        // codit-expect: CWE-915 entire request mass-assigned (two_factor_secret, is_admin, email_verified_at)
        $request->user()->update($request->all());

        return back()->with('status', 'profile-updated');
    }

    public function updateV2(ProfileUpdateRequest $request)
    {
        // codit-safe: CWE-915 only the validated name/locale/timezone fields are assigned
        $request->user()->update($request->validated());

        return back()->with('status', 'profile-updated');
    }
}

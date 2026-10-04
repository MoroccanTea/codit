<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ProfileController extends Controller
{
    public function update(Request $request)
    {
        $request->user()->update($request->all());   // codit-expect: CWE-915 every request field (is_admin, role) mass-assigned; User model has $guarded = []

        return back()->with('status', 'profile-updated');
    }

    public function updateDetails(Request $request)
    {
        $request->user()->update($request->only(['name', 'email', 'timezone']));   // codit-safe: CWE-915 explicit allow-list of fields

        return back()->with('status', 'profile-updated');
    }

    public function enableBeta(Request $request)
    {
        if ($request->header('X-Admin') === '1') {   // codit-expect: CWE-807 privilege decided by a client-supplied header
            $request->user()->forceFill(['beta' => true])->save();
        }

        return back();
    }
}

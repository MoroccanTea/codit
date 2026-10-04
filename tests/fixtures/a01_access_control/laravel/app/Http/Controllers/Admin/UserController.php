<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;

class UserController extends Controller
{
    public function index()
    {
        return view('admin.users.index', ['users' => User::orderBy('email')->paginate(50)]);
    }

    public function export()
    {
        return response()->streamDownload(function () {
            foreach (User::cursor() as $user) {
                echo $user->id . ',' . $user->email . PHP_EOL;
            }
        }, 'users.csv');
    }

    public function ban(Request $request, User $user)
    {
        $user->forceFill(['banned_at' => now()])->save();

        return back();
    }
}

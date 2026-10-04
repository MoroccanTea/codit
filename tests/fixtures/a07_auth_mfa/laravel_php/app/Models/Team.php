<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Team extends Model
{
    // codit-safe: CWE-915 explicit fillable allow-list, owner_id and plan are not mass assignable
    protected $fillable = ['name', 'description'];

    public function owner()
    {
        return $this->belongsTo(User::class, 'owner_id');
    }
}

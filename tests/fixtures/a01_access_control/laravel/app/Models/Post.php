<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Post extends Model
{
    protected $fillable = ['title', 'body', 'published_at', 'archived_at'];   // codit-safe: CWE-915 explicit $fillable without user_id or privileged columns

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}

<?php

namespace App\Http\Controllers;

use App\Models\Post;
use Illuminate\Http\Request;

class PostController extends Controller
{
    public function update(Request $request, int $id)
    {
        $post = Post::findOrFail($id);   // codit-expect: CWE-639 any post updated by id; no $this->authorize() or owner check
        $post->update($request->validate(['title' => 'required|string|max:200', 'body' => 'required|string']));

        return redirect()->route('posts.show', $post);
    }

    public function publish(Request $request, int $id)
    {
        $post = auth()->user()->posts()->findOrFail($id);   // codit-safe: CWE-639 lookup scoped through the authenticated user's relation
        $post->update(['published_at' => now()]);

        return redirect()->route('posts.show', $post);
    }

    public function archive(Request $request, int $id)
    {
        $post = Post::findOrFail($id);   // codit-safe: CWE-639 policy check $this->authorize('update', $post) right after
        $this->authorize('update', $post);
        $post->update(['archived_at' => now()]);

        return redirect()->route('posts.index');
    }

    public function destroy(Post $post)
    {
        $post->delete();

        return redirect()->route('posts.index');
    }
}

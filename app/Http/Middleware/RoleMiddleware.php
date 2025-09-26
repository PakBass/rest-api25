<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;
use App\Models\User;

class RoleMiddleware
{
    public function handle(Request $request, Closure $next, $role): Response
    {
        // Gunakan guard 'api' untuk JWT
        if (!Auth::guard('api')->check()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthenticated'
            ], 401);
        }

        $user = Auth::guard('api')->user();

        // Pastikan user adalah instance dari model User
        if (!$user instanceof User) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid user model'
            ], 500);
        }

        // Cek role dengan penanganan error
        try {
            if (!$user->hasRole($role)) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Unauthorized. Required role: ' . $role
                ], 403);
            }
        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Error checking user role',
                'error' => $e->getMessage()
            ], 500);
        }

        return $next($request);
    }
}

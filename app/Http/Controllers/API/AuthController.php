<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\Role;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name'      => 'required|string|max:255',
            'email'     => 'required|email|unique:users',
            'password'  => 'required|string|min:6|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status'    => 'error',
                'message'   => 'Validation failed',
                'errors'    => $validator->errors()
            ], 422);
        }

        $user = User::create([
            'name'      => $request->name,
            'email'     => $request->email,
            'password'  => Hash::make($request->password),
        ]);

        $user->assignRole('user'); // Assign role 'user' to the newly registered user

        $token = JWTAuth::fromUser($user);

        return response()->json([
            'status'    => 'Success',
            'message'   => 'User berhasil mendaftar',
            'data'      => [
                'user'  => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'avatar' => $user->avatar ?? null,
                    'roles' => $user->roles->pluck('name') // Tambahkan ini
                ],
                'token' => $this->respondWithToken($token)
            ]
        ], 201);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email'     => 'required|email|filled',
            'password'  => 'required|string|min:6|filled',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status'    => 'error',
                'message'   => 'Email dan password harus diisi',
                'errors'    => $validator->errors()
            ], 422);
        }

        $credentials = $request->only('email', 'password');

        try {
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json([
                    'status'    => 'error',
                    'message'   => 'Invalid credential'
                ], 401);
            }
        } catch (JWTException $e) {
            return response()->json([
                'status'    => 'error',
                'message'   => 'Token gagal dibuat',
                'error'     => $e->getMessage()
            ], 500);
        }

        // Ambil data user yang sedang login
        $user = auth('api')->user();

        return response()->json([
            'status'    => 'success',
            'message'   => 'Berhasil login',
            'data'      => array_merge(
                $this->respondWithToken($token),
                ['user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'avatar' => $user->avatar ?? null,
                    'roles' => $user->roles->pluck('name') // Tambahkan ini
                ]]
            )
        ]);
    }

    public function logout()
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());

            return response()->json([
                'status'    => 'success',
                'message'   => 'User berhasil logout'
            ]);
        } catch (JWTException $e) {
            return response()->json([
                'status'    => 'error',
                'message'   => 'Gagal logout, token tidak valid',
                'error'     => $e->getMessage()
            ], 500);
        }
    }

    public function refresh()
    {
        try {
            $newToken = JWTAuth::refresh(JWTAuth::getToken());

            return response()->json([
                'status'    => 'success',
                'message'   => 'Token telah diperbarui',
                'data'     => $this->respondWithToken($newToken)
            ]);
        } catch (JWTException $e) {
            return response()->json([
                'status'    => 'error',
                'message'   => 'Gagal memperbarui token',
                'error'     => $e->getMessage()
            ], 401);
        }
    }

    public function me()
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            return response()->json([
                'status'    => 'success',
                'message'   => 'User profile',
                'data'     => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'avatar' => $user->avatar ?? null,
                    'roles' => $user->roles->pluck('name') // Tambahkan ini
                ],
            ]);
        } catch (JWTException $e) {
            return response()->json([
                'status'    => 'error',
                'message'   => 'Token tidak valid atau expired token',
                'error'     => $e->getMessage()
            ], 401);
        }
    }

    public function assignUserRole(Request $request, $userId)
    {
        $validator = Validator::make($request->all(), [
            'role' => 'required|string|exists:roles,name'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $user = User::findOrFail($userId);
            $roleName = $request->role;

            // Hapus semua role yang ada
            $user->roles()->detach();

            // Tambahkan role baru
            $user->assignRole($roleName);

            return response()->json([
                'status' => 'success',
                'message' => "Role {$roleName} has been assigned to user {$user->name}",
                'data' => [
                    'user' => [
                        'id' => $user->id,
                        'name' => $user->name,
                        'email' => $user->email,
                        'roles' => $user->roles->pluck('name')
                    ]
                ]
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to assign role',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    // Tambahkan method untuk menghapus role user (hanya admin)
    public function removeUserRole(Request $request, $userId)
    {
        $validator = Validator::make($request->all(), [
            'role' => 'required|string|exists:roles,name'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $user = User::findOrFail($userId);
            $roleName = $request->role;

            // Hapus role yang ditentukan
            $user->removeRole($roleName);

            return response()->json([
                'status' => 'success',
                'message' => "Role {$roleName} has been removed from user {$user->name}",
                'data' => [
                    'user' => [
                        'id' => $user->id,
                        'name' => $user->name,
                        'email' => $user->email,
                        'roles' => $user->roles->pluck('name')
                    ]
                ]
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to remove role',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    // Tambahkan method untuk mengatur multiple role (hanya admin)
    public function syncUserRoles(Request $request, $userId)
    {
        $validator = Validator::make($request->all(), [
            'roles' => 'required|array',
            'roles.*' => 'string|exists:roles,name'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        try {
            $user = User::findOrFail($userId);
            $roles = $request->roles;

            // Sync roles
            $user->syncRoles($roles);

            return response()->json([
                'status' => 'success',
                'message' => "User roles have been updated",
                'data' => [
                    'user' => [
                        'id' => $user->id,
                        'name' => $user->name,
                        'email' => $user->email,
                        'roles' => $user->roles->pluck('name')
                    ]
                ]
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to sync roles',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    protected function respondWithToken($token)
    {
        return [
            'access_token'  => $token,
            'token_type'    => 'bearer',
            'expires_in' => JWTAuth::factory()->getTTL() * 60,

        ];
    }
}

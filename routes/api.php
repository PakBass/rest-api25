<?php

use App\Http\Controllers\API\AuthController;
use App\Http\Controllers\API\ProductController;
use App\Http\Controllers\API\UserController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

// Route::get('/user', function (Request $request) {
//     return $request->user();
// })->middleware('auth:sanctum');

// Route::prefix('auth')->name('auth')->group(function () {
//     Route::post('register', [AuthController::class, 'register'])->name('register');
//     Route::post('login', [AuthController::class, 'login'])->name('login');
//     Route::middleware('jwt')->group(function () {
//         Route::get('me', [AuthController::class, 'me'])->name('me');
//         Route::post('refresh', [AuthController::class, 'refresh'])->name('refresh');
//         Route::post('logout', [AuthController::class, 'logout'])->name('logout');
//         Route::apiResource('products', ProductController::class);
//     });
// });
// // Admin routes
// Route::group(['middleware' => ['auth:api', 'role:admin']], function () {
//     Route::get('users', [UserController::class, 'index']);
//     Route::get('users/{id}', [UserController::class, 'show']);
//     Route::put('users/{id}/role', [UserController::class, 'updateRole']);
// });

// Route::middleware('jwt')->group(function () {
// });

Route::prefix('auth')->name('auth.')->group(function () {
    Route::post('register', [AuthController::class, 'register'])->name('register');
    Route::post('login', [AuthController::class, 'login'])->name('login');
});

// Protected routes with JWT
Route::prefix('auth')->name('auth.')->middleware('jwt')->group(function () {
    Route::get('me', [AuthController::class, 'me'])->name('me');
    Route::post('refresh', [AuthController::class, 'refresh'])->name('refresh');
    Route::post('logout', [AuthController::class, 'logout'])->name('logout');

    // Products route - bisa diakses oleh semua user yang sudah login
    Route::apiResource('products', ProductController::class);

    // Admin management routes - hanya untuk admin
    Route::prefix('admin')->name('admin.')->middleware('role:admin')->group(function () {
        Route::get('users', [UserController::class, 'index'])->name('users.index');
        Route::get('users/{id}', [UserController::class, 'show'])->name('users.show');
        Route::put('users/{id}/role', [UserController::class, 'updateRole'])->name('users.updateRole');
    });

    // Manager dashboard - untuk admin dan manager
    Route::get('manager/dashboard', function () {
        return response()->json([
            'status' => 'success',
            'message' => 'Manager Dashboard'
        ]);
    })->name('manager.dashboard')->middleware('role:admin,manager');

    // User dashboard - untuk semua user yang sudah login
    Route::get('user/dashboard', function () {
        return response()->json([
            'status' => 'success',
            'message' => 'User Dashboard'
        ]);
    })->name('user.dashboard');
});

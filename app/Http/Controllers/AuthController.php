<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{

    public function login() {
        $validator = validator()->make(request()->all(), [
            'email'     => 'required|string|max:255',
            'password'  => 'required|string'
          ]);
        if($validator->fails()) {
            return response()->json($validator->errors());
        }
        $credentials = request()->only('email', 'password');
        if (! Auth::attempt($credentials)) {
            return response()->json([
                'message' => 'Unauthorized'
            ], 401); 
        }
        $user = User::where('email', request()->email)->firstOrFail();
        $token  = $user->createToken('auth_token')->plainTextToken;
        return response()->json([
            'message'       => 'Login success',
            'access_token'  => $token,
            'token_type'    => 'Bearer'
        ]);
    }

    public function logout() {
        Auth::user()->tokens()->delete();
        return response()->json([
            'message' => 'Logout successfull'
        ]);
    }

    public function register() {
        $validator = validator()->make(request()->all(), [
            'name'      => 'required|string|max:255',
            'email'     => 'required|string|max:255|unique:users',
            'password'  => 'required|string'
          ]);
        if ($validator->fails()) {
        return response()->json($validator->errors());
        }
        $user = User::create([
            'name'      => request()->name,
            'email'     => request()->email,
            'password'  => bcrypt(request()->password)
        ]);
        $token = $user->createToken('auth_token')->plainTextToken;
        return response()->json([
            'data'          => $user,
            'access_token'  => $token,
            'token_type'    => 'Bearer'
        ]);
    }

    public function me() {
        return response()->json(auth()->user());
    }

}

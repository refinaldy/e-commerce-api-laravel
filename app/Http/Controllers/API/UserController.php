<?php

namespace App\Http\Controllers\API;

use App\Helpers\ResponseFormatter;
use App\Models\User;
use Illuminate\Http\Request;
use Laravel\Fortify\Rules\Password;
use App\Http\Controllers\Controller;
use Exception;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    public function register(Request $request)
    {

        try {
            $request->validate([
                'name' => 'required|string|max:255',
                'username' => 'required|string|max:255|unique:users',
                'email' => 'email|required|max:255|unique:users',
                'phone' => 'required|string|max:255',
                'password' => ['required', 'string', new Password],
            ]);

            User::create([
                'name' => $request->name,
                'username' => $request->username,
                'email' => $request->email,
                'phone' => $request->phone,
                'password' => Hash::make($request->password),
            ]);

            $user = User::where('email', $request->email)->first();
            $tokenResult = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success(
                [
                    'access_token' => $tokenResult,
                    'token_type' => 'Bearer',
                    'user' => $user,
                ],
                'User Registered'
            );
        } catch (Exception $error) {
            return ResponseFormatter::error(
                [
                    'message' => 'Something went wrong',
                    'error' => $error,
                ],
                'Authentication Failed',
                500
            );
        }
    }

    public function login(Request $request)
    {
        try {
            $request->validate([
                'email' => "email|required",
                'password' => "required",
            ]);

            $credentials = request([
                'email',
                'password'
            ]);

            if (!Auth::attempt($credentials)) {
                return ResponseFormatter::error([
                    'message' => 'Unauthorized',
                ], 'Authentication Failed', 500);
            }

            $user = User::where('email', $request->email)->first();

            if (!Hash::check($request->password, $user->password, [])) {
                throw new \Exception('Invalid Credentials');
            }

            $tokenResult = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user,
            ], 'Authenticated');
        } catch (Exception $error) {
            return ResponseFormatter::error(
                [
                    'message' => 'Something went wrong',
                    'error' => $error,
                ],
                'Authentication Failed',
                500
            );
        }
    }

    public function fetch(Request $request)
    {
        return ResponseFormatter::success(
            $request->user(),
            'Data Profile User Berhasil Didapatkan'
        );
    }

    public function updateProfile(Request $request)
    {
        $usernameValidation = '';
        $emailValidation = '';
        $user = Auth::user();

        if ($request->username) {
            if ($request->username === $user->username) {
                $usernameValidation =  'required';
            } else {
                $usernameValidation =  'required|string|max:255|unique:users';
            }
        }

        if ($request->email) {
            if ($request->email === $user->email) {
                $emailValidation =  'required';
            } else {
                $emailValidation =  'email|required|max:255|unique:users';
            }
        }

        $request->validate([
            'name' => 'required|string|max:255',
            'username' => $usernameValidation,
            'email' => $emailValidation,
            'phone' => 'required|string|max:255',
            'password' => ['required', 'string', new Password],
        ]);

        $password = Hash::make($request->password);
        $data = $request->all();
        $data['password'] = $password;

        return ResponseFormatter::success($user, 'Profile Updated');
    }

    public function logout(Request $request)
    {
        $token = $request->user()->currentAccessToken()->delete();
        return ResponseFormatter::success(
            $token,
            'Token Revoked'
        );
    }
}

<?php

namespace App\Http\Controllers\api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|unique:users|max:255',
            'email' => 'required|unique:users|max:255',
            'password' => 'required|max:255',
            'confirm_password' => 'required|max:255|same:password',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => $validator->errors(),
            ], 400);
        }

        $user = User::create(array_merge(
            $validator->validated(),
            ['password' => bcrypt($request->password)]
        ));

        $success['token'] = $user->createToken('authToken')->plainTextToken;
        $success['name'] = $user->name;

        return response()->json([
            'status' => 'success',
            'message' => 'User created successfully',
            'data' => $success,
        ], 201);
    }

    public function login(Request $request)
    {
        if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            $auth = Auth::user();
            $success['token'] = $auth->createToken('authToken')->plainTextToken;
            $success['name'] = $auth->name;

            return response()->json([
                'status' => 'success',
                'message' => 'User login successfully',
                'data' => $success,
            ], 200);
        } else {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthorised',
            ], 401);
        }
    }
}

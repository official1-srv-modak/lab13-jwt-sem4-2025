package com.souravmodak.lab13jwt.service;

import com.souravmodak.lab13jwt.AuthApi;
import com.souravmodak.lab13jwt.model.AuthRequest;
import com.souravmodak.lab13jwt.model.AuthResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController implements AuthApi {

    @Autowired
    private AuthService authService;

    @Override
    public ResponseEntity<AuthResponse> authLoginPost(AuthRequest authRequest) {
        AuthResponse response = authService.login(authRequest);
        return ResponseEntity.ok(response);
    }
}
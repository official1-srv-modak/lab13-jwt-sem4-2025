package com.souravmodak.lab13jwt.service;

import com.souravmodak.lab13jwt.JwtHelperService;
import com.souravmodak.lab13jwt.Roles;
import com.souravmodak.lab13jwt.User;
import com.souravmodak.lab13jwt.UserRepo;
import com.souravmodak.lab13jwt.model.AuthRequest;
import com.souravmodak.lab13jwt.model.AuthResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {


    private final UserRepo repo;
    private final PasswordEncoder encoder;
    private final JwtHelperService jwtHelperService;

    @Autowired
    public AuthService(UserRepo repo, PasswordEncoder encoder, JwtHelperService jwtHelperService) {
        this.repo = repo;
        this.encoder = encoder;
        this.jwtHelperService = jwtHelperService;
    }

    public AuthResponse login(AuthRequest authRequest) {
        String token = "generated-jwt-token";

        User user = repo.findByUsername(authRequest.getUsername());
        if(user != null && encoder.matches(authRequest.getPassword(), user.getPassword()))
        {
            user.setPassword("");
            if(user.getRole().equalsIgnoreCase(Roles.ADMIN.getValue()))
            {
                token = jwtHelperService.generateToken(user, Roles.ADMIN);
                return new AuthResponse().token(token);
            }
            token = jwtHelperService.generateToken(user, Roles.USER);
            return new AuthResponse().token(token);
        }
        return null;
    }
}
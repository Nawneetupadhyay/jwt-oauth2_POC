package com.example.UserAuthentication.controller;


import com.example.UserAuthentication.models.Users;
import com.example.UserAuthentication.services.JwtService;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public AuthController(AuthenticationManager authenticationManager, JwtService jwtService, PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
    }

    // Login endpoint for JWT-based authentication
    @PostMapping("/login")
    public String authenticateUser(@RequestBody Users user) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtService.generateToken(authentication.getName());

        return jwt;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody Users request) {
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        return ResponseEntity.ok("User registered successfully");
    }

//    @GetMapping("/oauth2/success")
//    public ResponseEntity<String> oauth2Success() {
//        return ResponseEntity.ok("OAuth2 Authentication successful. Welcome, user!");
//    }
}

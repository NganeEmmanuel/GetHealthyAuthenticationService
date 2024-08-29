package com.gethealthy.authenticationservice.controller;

import com.gethealthy.authenticationservice.auth.AuthenticationRefreshResponse;
import com.gethealthy.authenticationservice.auth.AuthenticationRequest;
import com.gethealthy.authenticationservice.auth.AuthenticationResponse;
import com.gethealthy.authenticationservice.auth.RegisterRequest;
import com.gethealthy.authenticationservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@CrossOrigin
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(authService.signup(request));
    } //good

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(authService.login(request));
    } //good

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader){
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7); // Remove "Bearer " prefix
            return ResponseEntity.ok(authService.logout(token));
        } else {
            return ResponseEntity.badRequest().body("Invalid Authorization header.");
        }
    }

    @PostMapping("/authenticate-user")
    public ResponseEntity<Boolean> authenticateUser(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        System.out.println("Received authenticate-user request");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            var token = authorizationHeader.substring(7); // Remove "Bearer " prefix
            Boolean isAuthenticated = authService.authenticateUser(token);
            System.out.println("Authentication result: " + isAuthenticated);
            return ResponseEntity.ok(isAuthenticated);
        } else {
            return new ResponseEntity<>(Boolean.FALSE, HttpStatus.BAD_REQUEST);
        }
    }


    @PostMapping("/refresh-token")
    public ResponseEntity<AuthenticationRefreshResponse> refreshToken(@RequestBody String refreshToken) {
        return ResponseEntity.ok(authService.refreshToken(refreshToken));
    }

}

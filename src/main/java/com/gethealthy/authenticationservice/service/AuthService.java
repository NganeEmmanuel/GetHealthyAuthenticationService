package com.gethealthy.authenticationservice.service;


import com.gethealthy.authenticationservice.auth.AuthenticationRefreshResponse;
import com.gethealthy.authenticationservice.auth.AuthenticationRequest;
import com.gethealthy.authenticationservice.auth.AuthenticationResponse;
import com.gethealthy.authenticationservice.auth.RegisterRequest;
import com.gethealthy.authenticationservice.exception.AuthException;
import com.gethealthy.authenticationservice.model.UserDTO;
import org.springframework.http.ResponseEntity;

public interface AuthService {
    /**
     * Registers a new user in the system.
     *
     * @param request the user data transfer object containing the user's information
     * @throws AuthException if the user with the given email already exists or an error occurs during signup
     */
    ResponseEntity<AuthenticationResponse> signup(RegisterRequest request);

    /**
     * Authenticates a user and returns the user's data transfer object.
     *
     * @param request    contains the username and password of the user
     * @return the user data transfer object if the login is successful
     * @throws AuthException if the user with the given email is not found or the password is invalid
     */
    ResponseEntity<AuthenticationResponse> login(AuthenticationRequest request);

    /**
     * Authenticates a user and returns the user's data transfer object.
     *
     * @param token    token to be blacklisted
     * @return a success status and message is successful
     */
    ResponseEntity<String> logout(String token);

    /**
     * Registers a new user in the system.
     *
     * @param refreshToken the token to be refreshed
     * @return a refreshed authentication jwt token on success
     * @throws com.gethealthy.authenticationservice.exception.TokenExpiredException if token has expired
     */
    ResponseEntity<AuthenticationRefreshResponse> refreshToken(String refreshToken);

    /**
     * Registers a new user in the system.
     *
     * @param token the token to be authenticated
     * @return boolean ture if valid or false if not
     * @throws com.gethealthy.authenticationservice.exception.TokenExpiredException if token has expired
     */
    ResponseEntity<Boolean> authenticateUser(String token);

    /**
     * Get the user information from the authentication token
     *
     * @param token the token to be authenticated
     * @return userDTO object with user info if valid and an empty object if not
     * @throws com.gethealthy.authenticationservice.exception.TokenExpiredException if token has expired
     */
    ResponseEntity<UserDTO> getLoggedInUser(String token);

    /**
     * Get the userid information from the authentication token
     *
     * @param token the token to be authenticated
     * @return userDTO object with user info if valid and an empty object if not
     * @throws com.gethealthy.authenticationservice.exception.TokenExpiredException if token has expired
     */
    ResponseEntity<Long> getLoggedInUserId(String token);
}

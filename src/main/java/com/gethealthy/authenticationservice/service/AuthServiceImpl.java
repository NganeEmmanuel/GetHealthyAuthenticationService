package com.gethealthy.authenticationservice.service;

import com.gethealthy.authenticationservice.auth.AuthenticationRefreshResponse;
import com.gethealthy.authenticationservice.auth.AuthenticationRequest;
import com.gethealthy.authenticationservice.auth.AuthenticationResponse;
import com.gethealthy.authenticationservice.auth.RegisterRequest;
import com.gethealthy.authenticationservice.exception.NoMatchingUserFoundException;
import com.gethealthy.authenticationservice.exception.TokenExpiredException;
import com.gethealthy.authenticationservice.exception.UserNotVerifiedException;
import com.gethealthy.authenticationservice.feign.AuthenticationInterface;
import com.gethealthy.authenticationservice.model.TokenBlacklist;
import com.gethealthy.authenticationservice.model.User;
import com.gethealthy.authenticationservice.model.UserDTO;
import com.gethealthy.authenticationservice.repository.TokenBlacklistRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.http.ResponseEntity;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TokenBlacklistRepository tokenBlacklistRepository;
    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);
    private final AuthenticationInterface authenticationInterface;
    private final UserRequestWrapper userRequestWrapper;
    private final MapperService<UserDTO, User> mapperService;

    @Override
    public ResponseEntity<AuthenticationResponse> signup(RegisterRequest request) {
        request.setPassword(passwordEncoder.encode(request.getPassword()));
        var user = authenticationInterface.addUser(userRequestWrapper.toUserRequest(request)).getBody();
        assert user != null;

        // Generate JWT token using the username
        var jwtToken = jwtService.generateJwtToken(user.getUsername());
        return ResponseEntity.ok(AuthenticationResponse.builder()
                .token(jwtToken)
                .build());
    }

    @Override
    public ResponseEntity<AuthenticationResponse> login(AuthenticationRequest request) {
        try {
            var user = authenticationInterface.getUserByUsername(request.getUsername()).getBody();
            assert user != null;
            // Validate password
            if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                throw new RuntimeException("Invalid username or password");
            }

            // Generate JWT token using the username
            var jwtToken = jwtService.generateJwtToken(user.getUsername());
            return ResponseEntity.ok(AuthenticationResponse.builder()
                    .token(jwtToken)
                    .build());
        } catch (NoMatchingUserFoundException ex) {
            logger.info("Error getting user while logging in with username: {}", request.getUsername());
            throw new RuntimeException(ex);
        } catch (UserNotVerifiedException ex) {
            logger.info("Email not verified for user: {}", request.getUsername());
            throw new RuntimeException(ex);
        } catch (Exception e) {
            logger.info("Error occurred while logging in user: {}", request.getUsername());
            throw new RuntimeException(e);
        }
    }

    @Override
    public ResponseEntity<String> logout(String token) {
        var tokenBlacklist = TokenBlacklist.builder()
                .token(token)
                .expirationDate(jwtService.extractExpiration(token))
                .build();
        tokenBlacklistRepository.save(tokenBlacklist);
        return ResponseEntity.ok("success");
    }

    @Override
    public ResponseEntity<AuthenticationRefreshResponse> refreshToken(String refreshToken) {
        try {
            if (jwtService.isJwtTokenExpired(refreshToken)) {
                throw new TokenExpiredException();
            }
            var username = jwtService.extractUserName(refreshToken);
            var user = authenticationInterface.getUserByUsername(username).getBody(); // talks to user-service through Feign client
            assert user != null;
            var newJwtToken = jwtService.generateJwtToken(user.getUsername());
            return ResponseEntity.ok(AuthenticationRefreshResponse.builder()
                    .token(newJwtToken)
                    .build());
        } catch (TokenExpiredException expired) {
            logger.info("Expired token while refreshing token: {}", refreshToken);
            throw new RuntimeException(expired);
        } catch (NoMatchingUserFoundException ex) {
            logger.info("Error getting user from refresh token: {}", refreshToken);
            throw new RuntimeException(ex);
        }
    }

    @Override
    public ResponseEntity<Boolean> authenticateUser(String token) {
        try {
            var username = jwtService.extractUserName(token);
            var userResponse = authenticationInterface.getUserByUsername(username);

            if (userResponse.getStatusCode().is2xxSuccessful() && userResponse.getBody() != null) {
                return ResponseEntity.ok(jwtService.isJwtTokenValid(token));
            } else {
                return ResponseEntity.ok(Boolean.FALSE);
            }
        } catch (NoMatchingUserFoundException ex) {
            logger.info("Error getting user from token: {}", token);
            throw new RuntimeException(ex);
        } catch (Exception e) {
            logger.info("Error occurred while authenticating user: {}", token);
            throw new RuntimeException(e);
        }
    }

    @Override
    public ResponseEntity<UserDTO> getLoggedInUser(String token) {
        try {
            var userResponse = authenticationInterface.getUserByUsername(jwtService.extractUserName(token));

            if (userResponse.getStatusCode().is2xxSuccessful() && userResponse.getBody() != null) {
                var user = userResponse.getBody();
                if (jwtService.isJwtTokenValid(token)) {
                    return ResponseEntity.ok(mapperService.toDTO(user));
                }
            }

            return ResponseEntity.badRequest().body(new UserDTO());
        } catch (NoMatchingUserFoundException ex) {
            logger.info("Error getting logged in user from token: {}", token);
            throw new RuntimeException(ex);
        } catch (Exception e) {
            logger.info("Error occurred while getting logged in user from token: {}", token);
            throw new RuntimeException(e);
        }
    }

    public ResponseEntity<Long> getLoggedInUserId(String token) {
       var user = getLoggedInUser(token).getBody();
        assert user != null;
        return ResponseEntity.ok(user.getId());
    }
}

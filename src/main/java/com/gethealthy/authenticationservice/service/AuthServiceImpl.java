package com.gethealthy.authenticationservice.service;

import com.gethealthy.authenticationservice.auth.AuthenticationRefreshResponse;
import com.gethealthy.authenticationservice.auth.AuthenticationRequest;
import com.gethealthy.authenticationservice.auth.AuthenticationResponse;
import com.gethealthy.authenticationservice.auth.RegisterRequest;
import com.gethealthy.authenticationservice.enums.UserAuthority;
import com.gethealthy.authenticationservice.exception.NoMatchingUserFoundException;
import com.gethealthy.authenticationservice.exception.TokenExpiredException;
import com.gethealthy.authenticationservice.exception.UserNotVerifiedException;
import com.gethealthy.authenticationservice.feign.AuthenticationInterface;
import com.gethealthy.authenticationservice.model.TokenBlacklist;
import com.gethealthy.authenticationservice.model.User;
import com.gethealthy.authenticationservice.model.UserDTO;
import com.gethealthy.authenticationservice.repository.AuthenticationRepository;
import com.gethealthy.authenticationservice.repository.TokenBlacklistRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final AuthenticationRepository authRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TokenBlacklistRepository tokenBlacklistRepository;
    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);
    private final AuthenticationInterface authenticationInterface;
    private final UserRequestWrapper userRequestWrapper;
    private  final MapperService<UserDTO, User> mapperService;

    @Override
    public AuthenticationResponse signup(RegisterRequest request) {
        request.setPassword(passwordEncoder.encode(request.getPassword()));
        var user = authenticationInterface.addUser(userRequestWrapper.toUserRequest(request)).getBody();
            assert user != null;
            authRepository.save(user);

            //todo use openfiegn to implement the userService.saveUser() method
            var jwtToken = jwtService.generateJwtToken(user);
            return AuthenticationResponse.builder()
                    .token(jwtToken)
                    .build();
    }

    @Override
    public AuthenticationResponse login(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        try {
            var user = authenticationInterface.getUserByUsername(request.getUsername()).getBody();
            //todo configure mail connection and uncomment
            var jwtToken = jwtService.generateJwtToken(user);
            return AuthenticationResponse.builder()
                    .token(jwtToken)
                    .build();
        }catch (NoMatchingUserFoundException ex){
            logger.info("Error getting user while logging in with username: {}", request.getUsername());
            throw new RuntimeException(ex);
        }catch (UserNotVerifiedException ex){
            logger.info("Email not verified for user: {}", request.getUsername());
            throw new RuntimeException(ex);
        }catch (Exception e){
            logger.info("Error occurred while logging in user: {}", request.getUsername());
            throw new RuntimeException(e);
        }
    }

    @Override
    public String logout(String token) {
        var tokenBlacklist = TokenBlacklist.builder()
                .token(token)
                .expirationDate(jwtService.extractExpiration(token))
                .build();
        tokenBlacklistRepository.save(tokenBlacklist);
        return "User logged out successfully.";
    }

    @Override
    public AuthenticationRefreshResponse refreshToken(String refreshToken) {
        try {
            if (jwtService.isJwtTokenExpired(refreshToken)) {
                throw new TokenExpiredException();
            }
            var username = jwtService.extractUserName(refreshToken);
            var user = authenticationInterface.getUserByUsername(username).getBody(); //talks to user-service through feign client
            var newJwtToken = jwtService.generateJwtToken(user);
            return AuthenticationRefreshResponse.builder()
                    .token(newJwtToken)
                    .build();
        }catch (TokenExpiredException expired){
            logger.info("Expired token while refreshing token: {}", refreshToken);
            throw new RuntimeException(expired);
        }catch (NoMatchingUserFoundException ex){
            logger.info("Error getting user from refresh token: {}", refreshToken);
            throw new RuntimeException(ex);
        }
    }

    @Override
    public Boolean authenticateUser(String token) {
        try {
            var username = jwtService.extractUserName(token);
            var user = authenticationInterface.getUserByUsername(username).getBody();;

            return jwtService.isJwtTokenValid(token, user);
        }catch (NoMatchingUserFoundException ex){
            logger.info("Error getting user from token: {}", token);
            throw new RuntimeException(ex);
        }catch (Exception e){
            logger.info("Error occurred while authenticating user: {}", token);
            throw new RuntimeException(e);
        }
    }
}
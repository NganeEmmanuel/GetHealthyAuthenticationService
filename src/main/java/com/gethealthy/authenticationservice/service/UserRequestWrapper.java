package com.gethealthy.authenticationservice.service;

import com.gethealthy.authenticationservice.auth.RegisterRequest;
import com.gethealthy.authenticationservice.model.UserRequest;
import org.springframework.stereotype.Service;

@Service
public class UserRequestWrapper {
    public UserRequest toUserRequest(RegisterRequest registerRequest) {
        UserRequest userRequest = new UserRequest();
        userRequest.setName(registerRequest.getName());
        userRequest.setUsername(registerRequest.getUsername());
        userRequest.setEmail(registerRequest.getEmail());
        userRequest.setPassword(registerRequest.getPassword());
        return userRequest;
    }
}

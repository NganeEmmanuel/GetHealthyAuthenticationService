package com.gethealthy.authenticationservice.model;

import com.gethealthy.authenticationservice.enums.UserAuthority;
import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class UserRequest {
    private Long id;
    private String name;
    private String email;
    private String username;
    private String password;
    private UserAuthority authority;

    public UserRequest(String name, String email, String username, UserAuthority authority, String password) {
        this.name = name;
        this.email = email;
        this.username = username;
        this.authority = authority;
        this.password = password;
    }

    public UserRequest(String name, String email, String username, String password) {
        this.name = name;
        this.email = email;
        this.username = username;
        this.password = password;
    }
}

package com.gethealthy.authenticationservice.model;

import com.gethealthy.authenticationservice.enums.UserAuthority;
import lombok.*;

import java.util.*;

@NoArgsConstructor
@AllArgsConstructor
@Data
@ToString
@Builder
public class User{
    private Long id;

    private String name;

    private String username;

    private String email;

    private String password;

    private UserAuthority authority;

    private Date joinDate;

    private Date lastUpdated;

    public User(String name, String username, String email, String password){
        this.name = name;
        this.username = username;
        this.email = email;
        this.password = password;
    }
}

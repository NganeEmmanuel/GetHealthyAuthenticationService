package com.gethealthy.authenticationservice.model;

import com.gethealthy.authenticationservice.enums.UserAuthority;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class UserDTO {
    private Long id;
    private String name;
    private String email;
    private String username;
    private UserAuthority authority;

    public UserDTO(String name, String email, String username, UserAuthority authority) {
        this.name = name;
        this.email = email;
        this.username = username;
        this.authority = authority;
    }

    public UserDTO(String name, String email, String username) {
        this.name = name;
        this.email = email;
        this.username = username;
    }
}

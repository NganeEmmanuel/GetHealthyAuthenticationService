package com.gethealthy.authenticationservice.model;

import com.gethealthy.authenticationservice.enums.UserAuthority;
import jakarta.persistence.*;
import lombok.*;

import java.util.*;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Data
@ToString
@Builder
@Table(name = "users")
public class User{
    @Id
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserAuthority authority;

    @Temporal(TemporalType.TIMESTAMP)
    private Date joinDate;

    @Temporal(TemporalType.TIMESTAMP)
    private Date lastUpdated;

    public User(String name, String username, String email, String password){
        this.name = name;
        this.username = username;
        this.email = email;
        this.password = password;
    }

    @PrePersist
    protected void onCreate() {
        joinDate = new Date();
        lastUpdated = new Date();
    }
}

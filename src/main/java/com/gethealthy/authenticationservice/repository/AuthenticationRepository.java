package com.gethealthy.authenticationservice.repository;

import com.gethealthy.authenticationservice.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthenticationRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}


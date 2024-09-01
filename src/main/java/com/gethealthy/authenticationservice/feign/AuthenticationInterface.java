package com.gethealthy.authenticationservice.feign;

import com.gethealthy.authenticationservice.model.User;
import com.gethealthy.authenticationservice.model.UserDTO;
import com.gethealthy.authenticationservice.model.UserRequest;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

@Component
@FeignClient("USER-SERVICE")
public interface AuthenticationInterface {
    @GetMapping("/api/v1/user/get-with-username")
    ResponseEntity<User> getUserByUsername(@RequestParam String username);

    @PostMapping("/api/v1/user/add")
    ResponseEntity<UserDTO> addUser(@RequestBody UserRequest user);
}

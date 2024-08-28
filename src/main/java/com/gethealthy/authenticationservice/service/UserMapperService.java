package com.gethealthy.authenticationservice.service;


import com.gethealthy.authenticationservice.model.User;
import com.gethealthy.authenticationservice.model.UserDTO;
import org.springframework.stereotype.Service;

@Service
public class UserMapperService implements MapperService<UserDTO, User> {
    @Override
    public UserDTO toDTO(User user) {
        UserDTO userDTO = new UserDTO();
        userDTO.setId(user.getId());
        userDTO.setName(user.getName());
        userDTO.setUsername(user.getUsername());
        userDTO.setEmail(user.getEmail());
        userDTO.setAuthority(user.getAuthority());
        return userDTO;
    }

    @Override
    public User toEntity(UserDTO userDTO) {
        User user = new User();
        user.setId(userDTO.getId());
        user.setName(userDTO.getName());
        user.setEmail(userDTO.getEmail());
        user.setUsername(userDTO.getUsername());
        user.setAuthority(userDTO.getAuthority());
        return user;
    }

    @Override
    public void updateEntity(UserDTO userDTO, User user) {
        user.setName(userDTO.getName());
        user.setUsername(userDTO.getUsername());
        user.setEmail(userDTO.getEmail());
    }
}

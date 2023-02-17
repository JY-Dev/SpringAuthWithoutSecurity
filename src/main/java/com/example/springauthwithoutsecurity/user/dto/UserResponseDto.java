package com.example.springauthwithoutsecurity.user.dto;

import com.example.springauthwithoutsecurity.domain.user.Users;
import lombok.Getter;

@Getter
public class UserResponseDto {
    private String email;
    private String username;

    public UserResponseDto(Users users){
        this.email = users.getUserEmail();
        this.username = users.getUsername();
    }
}

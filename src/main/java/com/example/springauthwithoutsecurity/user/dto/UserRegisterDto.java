package com.example.springauthwithoutsecurity.user.dto;

import com.example.springauthwithoutsecurity.domain.user.Users;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UserRegisterDto {
    private String userEmail;

    private String password;

    private String username;

    public Users toEntity(){
        return Users.builder()
                .username(username)
                .email(userEmail)
                .password(password)
                .build();
    }
}

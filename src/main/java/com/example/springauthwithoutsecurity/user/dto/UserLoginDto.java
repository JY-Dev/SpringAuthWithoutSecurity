package com.example.springauthwithoutsecurity.user.dto;

import lombok.Getter;

@Getter
public class UserLoginDto {
    private String userEmail;
    private String userPassword;
}

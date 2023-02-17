package com.example.springauthwithoutsecurity.filter;

import com.example.springauthwithoutsecurity.domain.user.Role;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Set;

@Getter
@AllArgsConstructor
public class AuthenticateUser {
    private String email;
    private Set<Role> roles;
}

package com.example.springauthwithoutsecurity.user.dto;

import com.example.springauthwithoutsecurity.domain.user.Role;
import lombok.Builder;
import lombok.Getter;

import java.util.Set;

@Builder
@Getter
public class UserVerifyResponseDto {
    private boolean isValid;
    private Set<Role> userRole;
}

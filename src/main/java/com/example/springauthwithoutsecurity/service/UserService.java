package com.example.springauthwithoutsecurity.service;

import com.example.springauthwithoutsecurity.domain.jwt.Jwt;
import com.example.springauthwithoutsecurity.domain.jwt.JwtProvider;
import com.example.springauthwithoutsecurity.domain.user.*;
import com.example.springauthwithoutsecurity.filter.AuthenticateUser;
import com.example.springauthwithoutsecurity.filter.VerifyUserFilter;
import com.example.springauthwithoutsecurity.user.dto.UserLoginDto;
import com.example.springauthwithoutsecurity.user.dto.UserRegisterDto;
import com.example.springauthwithoutsecurity.user.dto.UserResponseDto;
import com.example.springauthwithoutsecurity.user.dto.UserVerifyResponseDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;

    private final UserRoleRepository userRoleRepository;

    private final JwtProvider jwtProvider;

    private final ObjectMapper objectMapper;

    @Transactional
    public UserResponseDto registerUser(UserRegisterDto userRegisterDto){
        Users user = userRepository.save(userRegisterDto.toEntity());
        UserRole role = UserRole.builder()
                .role(Role.USER)
                .user(user)
                .build();
        user.addRole(role);
        userRoleRepository.save(role);
        return new UserResponseDto(user);
    }

    public UserVerifyResponseDto verifyUser(UserLoginDto userLoginDto){
        Users user = userRepository.findByUserEmail(userLoginDto.getUserEmail());
        if(user == null)
            return UserVerifyResponseDto.builder()
                    .isValid(false)
                    .build();
        return UserVerifyResponseDto.builder()
                .isValid(true)
                .userRole(user.getUserRoles().stream().map(UserRole::getRole).collect(Collectors.toSet())).build();
    }

    public UserResponseDto findUserByEmail(String userEmail){
        return new UserResponseDto(userRepository.findByUserEmail(userEmail));
    }

    @Transactional
    public void updateRefreshToken(String userEmail,String refreshToken){
        Users user = userRepository.findByUserEmail(userEmail);
        if(user == null)
            return;
        user.updateRefreshToken(refreshToken);
    }

    @Transactional
    public Jwt refreshToken(String refreshToken){
        try{
            // 유효한 토큰 인지 검증
            jwtProvider.getClaims(refreshToken);
            Users user = userRepository.findByRefreshToken(refreshToken);
            if(user == null)
                return null;

            HashMap<String, Object> claims = new HashMap<>();
            AuthenticateUser authenticateUser = new AuthenticateUser(user.getUserEmail(),
                    user.getUserRoles().stream().map(UserRole::getRole).collect(Collectors.toSet()));
            String authenticateUserJson = objectMapper.writeValueAsString(authenticateUser);
            claims.put(VerifyUserFilter.AUTHENTICATE_USER,authenticateUserJson);
            Jwt jwt = jwtProvider.createJwt(claims);
            updateRefreshToken(user.getUserEmail(),jwt.getRefreshToken());
            return jwt;
        } catch (Exception e){
            return null;
        }
    }

    @Transactional
    public boolean addUserRole(String email, Role role){
        Users users = userRepository.findByUserEmail(email);
        if(users.getUserRoles().stream().anyMatch(userRole -> userRole.getRole().equals(role)))
            return false;
        UserRole userRole = UserRole.builder()
                .user(users)
                .role(role)
                .build();
        users.addRole(userRole);
        userRoleRepository.save(userRole);
        return true;
    }
}

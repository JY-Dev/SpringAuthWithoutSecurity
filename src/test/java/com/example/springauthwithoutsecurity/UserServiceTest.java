package com.example.springauthwithoutsecurity;

import com.example.springauthwithoutsecurity.domain.user.Role;
import com.example.springauthwithoutsecurity.domain.user.Users;
import com.example.springauthwithoutsecurity.service.UserService;
import com.example.springauthwithoutsecurity.user.dto.UserRegisterDto;
import com.example.springauthwithoutsecurity.user.dto.UserResponseDto;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

@Transactional
@SpringBootTest
public class UserServiceTest {
    @Autowired
    private UserService userService;

    @Test
    public void registerUserTest(){
        userService.registerUser(UserRegisterDto.builder()
                .userEmail("email")
                .username("username")
                .password("password")
                .build());
        UserResponseDto user = userService.findUserByEmail("email");
        Assertions.assertThat(user.getEmail()).isEqualTo("email");
        Assertions.assertThat(user.getUsername()).isEqualTo("username");
    }

    @Test
    public void addUserRoleTest(){
        userService.registerUser(UserRegisterDto.builder()
                .userEmail("email")
                .username("username")
                .password("password")
                .build());
        boolean addRole = userService.addUserRole("email", Role.ADMIN);
        Assertions.assertThat(addRole).isEqualTo(true);
        boolean fail = userService.addUserRole("email", Role.ADMIN);
        Assertions.assertThat(fail).isEqualTo(false);
    }
}

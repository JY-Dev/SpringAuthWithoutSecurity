package com.example.springauthwithoutsecurity.user;

import com.example.springauthwithoutsecurity.service.UserService;
import com.example.springauthwithoutsecurity.user.dto.UserRegisterDto;
import com.example.springauthwithoutsecurity.user.dto.UserResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
@RequestMapping("/user")
public class UserController {
    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<UserResponseDto> register(@RequestBody UserRegisterDto userRegisterDto){
        return ResponseEntity.ok(userService.registerUser(userRegisterDto));
    }
}

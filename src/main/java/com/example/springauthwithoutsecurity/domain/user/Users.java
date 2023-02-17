package com.example.springauthwithoutsecurity.domain.user;

import com.example.springauthwithoutsecurity.user.dto.UserLoginDto;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@NoArgsConstructor
@Getter
@Entity
public class Users {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    @Column(name = "user_seq_id")
    private Long userSeqId;

    @Column(name = "user_email",nullable = false, unique = true)
    private String userEmail;

    private String password;

    private String username;

    private String refreshToken;

    @OneToMany(mappedBy = "user",cascade = CascadeType.REMOVE, fetch = FetchType.EAGER)
    private Set<UserRole> userRoles = new HashSet<>();

    @Builder
    public Users(String email, String password, String username){
        this.userEmail = email;
        this.password = password;
        this.username = username;
    }

    public void addRole(UserRole userRole){
        userRoles.add(userRole);
    }

    public void updateRefreshToken(String refreshToken){
        this.refreshToken = refreshToken;
    }

    public boolean verifyUser(UserLoginDto userLoginDto){
        return this.userEmail.equals(userLoginDto.getUserEmail()) && this.password.equals(userLoginDto.getUserPassword());
    }
}

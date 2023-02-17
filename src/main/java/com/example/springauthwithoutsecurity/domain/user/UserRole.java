package com.example.springauthwithoutsecurity.domain.user;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@Entity
public class UserRole {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private Long userRoleId;
    @ManyToOne
    @JoinColumn(name = "user_id")
    private Users user;

    @Enumerated(value = EnumType.STRING)
    private Role role;

    @Builder
    public UserRole(Users user ,Role role){
        this.user = user;
        this.role = role;
    }
}

package com.example.springauthwithoutsecurity.domain.user;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Users,Long> {
    Users findByUserEmail(String userEmail);

    Users findByRefreshToken(String refreshToken);
}

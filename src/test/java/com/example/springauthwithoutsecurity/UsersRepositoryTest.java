package com.example.springauthwithoutsecurity;

import com.example.springauthwithoutsecurity.domain.user.Users;
import com.example.springauthwithoutsecurity.domain.user.UserRepository;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

@DataJpaTest
public class UsersRepositoryTest {
    @Autowired
    UserRepository userRepository;

    @Test
    public void findByUserEmailTest(){
        Users saveUser = userRepository.save(new Users("email", "password", "username"));
        Users result = userRepository.findByUserEmail("email");
        Assertions.assertThat(saveUser).isEqualTo(result);
    }

    @Test
    public void updateRefreshTokenTest(){
        String refreshToken = "Token";
        String email = "email";
        Users saveUser = userRepository.save(new Users(email, "password", "username"));
        Assertions.assertThat(saveUser.getRefreshToken()).isNull();
        saveUser.updateRefreshToken(refreshToken);
        Users findUser = userRepository.findByUserEmail(email);
        Assertions.assertThat(findUser.getRefreshToken()).isEqualTo(refreshToken);
    }
}

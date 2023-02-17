package com.example.springauthwithoutsecurity;

import com.example.springauthwithoutsecurity.domain.jwt.Jwt;
import com.example.springauthwithoutsecurity.domain.jwt.JwtProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtProviderTest {
    private final JwtProvider jwtProvider = new JwtProvider();
    @Test
    public void tokenExpiredTest() throws InterruptedException {
        String token = jwtProvider.createToken(new HashMap<>(), new Date(System.currentTimeMillis() + 100));
        Thread.sleep(100);
        Assertions.assertThrows(ExpiredJwtException.class,() -> jwtProvider.getClaims(token));
    }

    @Test
    public void getClaimsTest() {
        Map<String,Object> claims = new HashMap<>();
        String userEmailKey = "userEmail";
        String userEmail = "userEmail";
        claims.put(userEmailKey,userEmail);
        Jwt token = jwtProvider.createJwt(claims);
        Claims claimsResult = jwtProvider.getClaims(token.getAccessToken());
        org.assertj.core.api.Assertions.assertThat(claimsResult.get(userEmailKey)).isEqualTo(userEmail);
    }
}

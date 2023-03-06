# Spring Security 없이 Spring JWT 인증 인가 구현해보기

아마 대부분 Spring Framework를 통해 개발하게 되면 사용자에 대한 인증과 인가를 Spring Security를 통해 간단하게 구현할 수 있을 것입니다. Spring Security를 공부하기 전에 Spring Security를 사용하지 않고 직접 구현해 보면 Spring Security를 통해 구현하는 인증과 인가 부분을 잘 이해할 수 있지 않을까 라는 생각으로 진행해보려고 합니다. 그래서 필터 그리고 JWT을 이용해서 인증과 인가를 구현해 도록 하겠습니다. 

### JWT란 무엇인가?

JWT는 Json Web Token의 약자입니다. JWT는 당사자 간의 정보를 JSON으로 안전하게 전송하기 위한 Claim기반의 Web Token 입니다. 이 정보는 HMAC 또는 RSA를 사용하는 공개키/개인키를 통해 서명할 수 있기 때문에 신뢰할 수 있습니다. 그래서 해당 토큰을 통해 사용자를 식별하고 리소스에 접근해서 리소스를 가져올 수 있습니다. JWT의 구조는 Header, Payload, Signature 3개로 나뉩니다. 이 3개는 “.” 구분자를 통해 구분됩니다. 그래서 각 부분은 Base64로 인코딩 됩니다. 각 구조에 대해 한번 알아보도록 하겠습니다.

**Header**는 토큰의 타입과 사용중인 서명 알고리즘에 대한 값이 들어가 있습니다. JWT에서 가장 첫번째 부분을 담당 합니다.

**Payload**는 Claim들을 포함하고 있고 JWT에서 두번째 부분을 담당 하고 있습니다. Claim은 사용자에 대한 데이터를 이야기합니다. 그래서 발급자, 토큰 만료시간, 식별자 등을 포함할 수 있습니다.

**Singnature**는 Base64로 인코딩된 Header와 Payload 그리고 secret을 헤더에 있는 알고리즘을 통한 암호화로 생성할 수 있고 중간에 메세지가 변경되지 않았는지 확인하는데 사용됩니다.

Base64를 통해 데이터가 인코딩 되었기 때문에 토큰에는 제3자가 알면 안되는 중요한 정보를 담지 말아야 합니다. 또한 일반적으로 헤더를 통해 전송이 되기 때문에 너무 큰 데이터를 담으면 안됩니다. 

### JwtProvider 구현

JwtProvider는 Jwt을 생성하고 파싱하는 클래스입니다. 그래서 JwtProvider를 통해 AccessToken과 refreshToken을 생성하고 생성된 토큰을 parsing해서 Claims로 반환하는 메서드를 구현해보겠습니다. 먼저 Jwt를 직접 만들고 파싱하는 과정은 쉽지 않기 때문에 [jjwt 라이브러리](https://github.com/jwtk/jjwt#jws-key-create)를 사용하였습니다. jjwt 라이브러리를 통해 먼저 토큰 생성하는 로직을 작성해 보겠습니다. 일단 토큰을 생성하기 위해 아래와 같이 secret key를 선언해주도록 하겠습니다.

```java
public static final byte[] secret = "JaeYoungSecretKeyJaeYoungSecretKeyJaeYoungSecretKey".getBytes();
private final Key key = Keys.hmacShaKeyFor(secret);
```

사용하고자 하는 secret key를 byte 배열로 변환해주고 Keys.hmacShaKeyFor를 통해 Key로 만들어줍니다. hmacShaKeyFor는 HMAC-SHA 알고리즘을 통해 secret key에 대해 암호화를 시켜주게 됩니다. 이때 주의해야하는 점이 secret key가 32 bytes 미만일 경우 WeakKeyException이 발생하게 됩니다. 해당 익셉션은 보안상 위험하기 때문에 발생하게 됩니다. 라이브러리를 사용해서 그런지 토큰 생성하는 로직은 길지 않습니다. 

```java
public String createToken(Map<String, Object> claims, Date expireDate) {
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(expireDate)
                .signWith(key)
                .compact();
    }
```

Jwts.builder를 통해 토큰을 생성해 줄 수 있는데요 하나하나 살펴보도록 하겠습니다. setClaims는 토큰에 claim을 설정해주는 메서드이고 setExpiration은 토큰 만료기간을 설정해주는 메서드입니다. signWith은 아까 선언한 key를 설정해줘서 나중에 토큰을 검증할 때 사용하게 됩니다. compact를 통해 토큰을 발행하게 됩니다. 이러한 토큰은 JWS라고 불립니다. JWS는 서버에서 인증을 근거로 인증정보를 서버의 private key로 서명 한것을 토큰화 한것입니다. 토큰을 생성했으니 이제 토큰에서 claims를 가져오는 로직에 대해 알아보겠습니다. 

```java
public Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
```

parserBuilder를 통해 JwtParser를 가져올 수 있습니다 이때 parserBuilder에 설정해줘야하는건 아까 토큰 생성할 때 설정해준 key를 넣어주도록 합니다. 그래서 build를 통해 JwtParser를 가져오게 되고 parserClaimsJws를 통해 Jws의 claims를 파싱해줍니다. 이때 발생할 수 익셉션은 여러가지가 있는데 중요한익셉션은 아래와 같습니다.

- SignatureException
    - signature 검증이 실패했을 때 발생합니다
- MalformedJwtException
    - JWS 형식에 맞지 않을 때 발생합니다.
- ExpiredJwtException
    - 토큰이 만료되었을 때 발생합니다.

최종적으로 getBody 메서드를 통해 Claims를 얻어올 수 있습니다.

이를 기반으로 AccessToken과 RefreshToken을 생성하고 반환하는 메서드를 만들어 보겠습니다. 

일단 jwt라는 accessToken과 refreshToken을 담는 클래스를 생성해줍니다.

```java
@Getter
public class Jwt {
    private String accessToken;
    private String refreshToken;

    @Builder
    public Jwt(String accessToken, String refreshToken){
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
}
```

그리고 TokenExpire에 대한 Date를 반환해주는 메서드와 Jwt객체를 반환하는 메서드를 만들어 줍니다.

```java
public Jwt createJwt(Map<String, Object> claims) {
        String accessToken = createToken(claims, getExpireDateAccessToken());
        String refreshToken = createToken(new HashMap<>(), getExpireDateRefreshToken());
        return Jwt.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

public Date getExpireDateAccessToken() {
    long expireTimeMils = 1000 * 60 * 60;
    return new Date(System.currentTimeMillis() + expireTimeMils);
 }

public Date getExpireDateRefreshToken() {
    long expireTimeMils = 1000L * 60 * 60 * 24 * 60;
    return new Date(System.currentTimeMillis() + expireTimeMils);
}
```

이때 refreshToken에는 보안상 문제때문에 아무런 Cliams를 포함하지 않도록 합니다.

### 간단한 회원가입

간단하게 회원가입을 구현하겠습니다. 일단 User 클래스와 권한을 담당하는 UserRole 클래스를 만들어보겠습니다.

```java
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
    private Role role;

    @Builder
    public UserRole(Users user ,Role role){
        this.user = user;
        this.role = role;
    }
}
```

```java
package com.example.springauthwithoutsecurity.domain.user;

public enum Role {
    ADMIN,USER
}
```

Role은 어드민과 일반유저 이렇게 나뉘어져있습니다.

```java
package com.example.springauthwithoutsecurity.domain.user;

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
}
```

userSeqId, userEmail, password, username, refreshToken, role만 담고있는 아주 간단한 유저정보 입니다. 일단 DB에 저장하기 위해 JPA를 사용하였고 Entity로 선언하였습니다. 회원가입시에 User를 저장하기 위해 refreshToken을 제외한 나머지 필드를 인자로 받는 생성자를 생성하였습니다. 그리고 updateRefreshToken을 라는 refreshToken을 별도로 저장할 수 있는 메서드도 구현하였습니다. Database에 저장하기 위한 Repository를 만들어 주도록 합시다. Database는 H2 database를 사용하였고 Spring Data Jpa로 구현해보도록 하겠습니다. 의존성과 database 설정은 아래와 같이 추가해주도록 합시다.

```groovy
dependencies{
	runtimeOnly 'com.h2database:h2'
	implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
}
```

```java
spring.h2.console.enabled=true
spring.h2.console.settings.web-allow-others=true
spring.datasource.generate-unique-name = false 
spring.h2.console.path=/h2-console
spring.datasource.url=jdbc:h2:mem:testdb
spring.datasource.driverClassName=org.h2.Driver
```

```java
public interface UserRepository extends JpaRepository<Users,Long> {
    Users findByUserEmail(String userEmail);
}
```

Spring Data Jpa를 통해 Repository를 생성해주었고 userEmail로 사용자를 검색하는 메서드를 추가하였습니다. 다음으로는 트랜잭션 처리를 위해 Service를 만들어 주도록 하겠습니다. Service에 필요한 DTO를 추가하였습니다.

```java
public class UserLoginDto {
    private String userEmail;
    private String userPassword;
}
```

```java
@Getter
public class UserRegisterDto {
    private String userEmail;

    private String password;

    private String username;

    public Users toEntity(){
        return Users.builder()
                .username(username)
                .email(userEmail)
                .password(password)
                .build();
    }
}
```

```java
@Getter
public class UserResponseDto {
    private String email;
    private String username;

    public UserResponseDto(Users users){
        this.email = users.getUserEmail();
        this.username = users.getUsername();
    }
}
```

```java
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
```

```java
@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;

    private final UserRoleRepository userRoleRepository;

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
```

유저를 등록하는 registerUser, Email을 기반으로 User를 검색하는 findUserByEmail, RefreshToken을 갱신하기 위한 updateRefreshToken, Role 즉 권한을 추가하기 위한 addUserRole 메서드를 추가해 주었습니다. 다음으로는 UserController에 회원가입하는 로직을 추가해 주도록 합시다.

```java
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
```

### 필터를 통한 로그인 검증 처리

로그인 요청을 했을 때 필터를 통해 User를 검증하고 Jwt를 반환해주는 로직을 작성해도록 하겠습니다. User를 검증하는 VerifyUserFilter와 AuthenticateUser라는 인증된 User에 대한 객체인 AuthenticateUser를 먼저 생성해주도록 하겠습니다.

```java
@Getter
@AllArgsConstructor
public class AuthenticateUser {
    private String email;
		private Set<Role> roles;
}
```

간단하게 만들것이기 때문에 email하고 Role만 추가해줬습니다.

```java
@Slf4j
@RequiredArgsConstructor
@Component
public class VerifyUserFilter implements Filter {
    public static final String AUTHENTICATE_USER = "authenticateUser";
    private final ObjectMapper objectMapper;

    private final UserService userService;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        if ((httpServletRequest.getMethod().equals("POST"))) {
            try {
                UserLoginDto userLoginDto = objectMapper.readValue(request.getReader(), UserLoginDto.class);
                UserVerifyResponseDto verifyResponse = userService.verifyUser(userLoginDto);
                if (verifyResponse.isValid()) {
                    request.setAttribute(AUTHENTICATE_USER, new AuthenticateUser(userLoginDto.getUserEmail(),verifyResponse.getUserRole()));
                } else
                    throw new IllegalArgumentException();
                chain.doFilter(request, response);
            } catch (Exception e) {
                log.error("Fail User Verify");
                HttpServletResponse httpServletResponse = (HttpServletResponse) response;
                httpServletResponse.sendError(HttpStatus.BAD_REQUEST.value());
            }
        }
    }

```

HttpMethod가 Post인 경우에만 동작하고 objectMapper를 통해 Json 요청값을 UserLoginDto로 변환해 주고 해당 User가 실제 있는 유저인지 userService에 있는 verifyUser를 통해 검증을 하게 됩니다.검증에 성공했다면 인증에 필요한 AuthenticateUser를 setArribute를 통해 request에 포함시켜줍니다. 이 값은 다음 필터에서 사용되게 됩니다. 만약 검증에 실패했다면 IllegalArgumentException 익셉션을 발생시킵니다. 정상적으로 검증이 되었다면 다음 필터를 동작하게 되고 예외가 발생한 경우 sendError를 통해 BAD_REQUEST 에러를 보냅니다. 다음으로 JwtEndPointFilter라는 User검증이 된후에 Jwt를 반환하는 필터를 생성해주도록 하겠습니다.

```java
@RequiredArgsConstructor
public class JwtFilter implements Filter {

    private final JwtProvider jwtProvider;

    private final ObjectMapper objectMapper;

    private final UserService userService;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException {
        Object attribute = request.getAttribute(VerifyUserFilter.AUTHENTICATE_USER);
        if (attribute instanceof AuthenticateUser authenticateUser) {
            Map<String, Object> claims = new HashMap<>();
            String authenticateUserJson = objectMapper.writeValueAsString(authenticateUser);
            claims.put(VerifyUserFilter.AUTHENTICATE_USER, authenticateUserJson);
            Jwt jwt = jwtProvider.createJwt(claims);
            userService.updateRefreshToken(authenticateUser.getEmail(), jwt.getRefreshToken());
            String json = objectMapper.writeValueAsString(jwt);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(json);
            return;
        }

        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        httpServletResponse.sendError(HttpStatus.BAD_REQUEST.value());
    }
}
```

직전에 넣어줬던 AuthenticateUser를 가져오게 되는데 만약 값이 없다면 BAD_REQUEST를 던져주게 됩니다. 제대로 가져온 경우에는 AuthenticateUser를 claims에 포함시킵니다. 그리고 jwtProvider를 통해 jwt를 생성해주고 refreshToken은 따로 데이터베이스에 저장해줍니다. 그리고 jwt를 response를 통해 json형태로 반환해줍니다. 이제 이렇게 생성한 필터를 등록을 해줘야하는데요 FilterRegisterationBean을 통해 등록해주도록 하겠습니다. FilterRegisterationBean를 등록하기 위한 WebConfig라는 Configuration 클래스를 생성해주도록 하겠습니다. 

```java
@Configuration
public class WebConfig {

    @Bean
    public FilterRegistrationBean verifyUserFilter(ObjectMapper mapper, UserService userService) {
        FilterRegistrationBean<Filter> filterRegistrationBean = new
                FilterRegistrationBean<>();
        filterRegistrationBean.setFilter(new VerifyUserFilter(mapper,userService));
        filterRegistrationBean.setOrder(1);
        filterRegistrationBean.addUrlPatterns("/user/login");
        return filterRegistrationBean;
    }

    @Bean
    public FilterRegistrationBean jwtFilter(JwtProvider provider, ObjectMapper mapper, UserService userService) {
        FilterRegistrationBean<Filter> filterRegistrationBean = new
                FilterRegistrationBean<>();
        filterRegistrationBean.setFilter(new JwtFilter(provider,mapper,userService));
        filterRegistrationBean.setOrder(2);
        filterRegistrationBean.addUrlPatterns("/user/login");
        return filterRegistrationBean;
    }
}
```

FilterRegisterationBean을 통해 등록하면 setFilter를 통해 filter를 등록할 수 있고 setOrder를 통해 순서를 지정해 줄 수 있습니다. 그리고 addUrlPatterns를 통해 filter를 동작시킬 uri 패턴을 등록해 줄 수 있습니다. 그래서 verifyUserFilter가 가장 먼저 호출되고 그다음 jwtEndPointFilter가 호출되도록 order를 지정해줍니다. 이 필터는 login을 할 때만 필요하기 때문에 /user/login 인 경우에만 동작하도록 설정하였습니다. 그리고 application.properties에 아래와 같은 하나의 설정을 추가해주셔야합니다. 

```java
spring.main.allow-bean-definition-overriding=true
```

### Jwt 갱신 로직 작성하기

Jwt의 accessToken이 만료되면 갱신을 해야하는데요 accessToken을 갱신하는 로직을 작성해 보도록 하겠습니다. 

일단 토큰이 생성되고 갱신되는 흐름에 대해 먼저 이야기 해보도록하겠습니다. 

1. User Login시에 accessToken이랑 refreshToken 생성
2.  user 테이블에 refreshToken을 저장
3. 시간이 지난뒤에 accessToken 만료
4. token refresh 요청
5. refreshToken으로 user를 조회
6. 조회된 User가 있으면 accessToken이랑 refreshToken 갱신
7. user 테이블에 refreshToken을 저장
8. accessToken과 refreshToken을 response로 반환

이제 토큰 갱신을 위해 UserService에 refreshToken으로 User에 대한 정보를 가져오고 토큰을 갱신하는 로직을 작성해보도록 하겠습니다.

```java
public interface UserRepository extends JpaRepository<Users,Long> {
    Users findByRefreshToken(String refreshToken);
}
```

UserRepository에 RefreshToken으로 User를 조회하는 메서드를 추가해주도록 합시다.

```java
private final JwtProvider jwtProvider;

private final ObjectMapper objectMapper;

@Transactional
    public Jwt refreshToken(String refreshToken){
        Users user = userRepository.findByRefreshToken(refreshToken);
        if(user == null)
            return null;
        try{
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
```

갱신하는 로직을 보자면 먼저 refreshToken으로 user을 조회합니다. 만약 유저가 존재하지 않는다면 Null을 반환해주고 AuthenticateUser를 생성해줍니다. 그리고 Json 형태로 만들어주고 Calims에 넣어줍니다. 그다음  jwt 토큰을 생성해주고 refreshToken을 user 테이블에 저장해줍니다. 정상적으로 저장이 되었다면 jwt를 return 해줍니다. 다음으로 AuthController를 생성해서 tokenRefresh 요청을 받아 토큰갱신을 처리하도록 하겠습니다. 

```java
@Getter
public class TokenRefreshDto {
    private String refreshToken;
}
```

```java
@RequiredArgsConstructor
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;

    @PostMapping("/refresh/token")
    public ResponseEntity<Jwt> tokenRefresh(@RequestBody TokenRefreshDto tokenRefreshDto) {
        Jwt jwt = userService.refreshToken(tokenRefreshDto.getRefreshToken());
        if (jwt == null){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(null);
        }
        return ResponseEntity.ok(jwt);
    }  
}
```

만약 jwt가 null이라면 401 에러코드를 반환하고 jwt가 null이 아니라면 jwt를 반환해주도록 합니다. 

### 인가 처리

이제 권한에 대한 인가처리를 위해 요청한 Jwt에 대해 인가해주는 JwtAuthorizationFilter를 생성해 주도록 하겠습니다. 

```java
@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter implements Filter {
    private final String[] whiteListUris = new String[]{"/user/login","/auth/refresh/token","/user/register","*/h2-console*"};

    private final JwtProvider jwtProvider;

    private final ObjectMapper objectMapper;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        if(whiteListCheck(httpServletRequest.getRequestURI())){
            chain.doFilter(request, response);
            return;
        }
        if(!isContainToken(httpServletRequest)){
            httpServletResponse.sendError(HttpStatus.UNAUTHORIZED.value(),"인증 오류");
            return;
        }
        try{
            String token = getToken(httpServletRequest);
            AuthenticateUser authenticateUser = getAuthenticateUser(token);
            verifyAuthorization(httpServletRequest.getRequestURI(),authenticateUser);
            log.info("값 : {}",authenticateUser.getEmail());
            chain.doFilter(request, response);
        } catch (JsonParseException e){
            log.error("JsonParseException");
            httpServletResponse.sendError(HttpStatus.BAD_REQUEST.value());
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException e){
            log.error("JwtException");
            httpServletResponse.sendError(HttpStatus.UNAUTHORIZED.value(), "인증 오류");
        } catch (ExpiredJwtException e){
            log.error("JwtTokenExpired");
            httpServletResponse.sendError(HttpStatus.FORBIDDEN.value(), "토큰이 만료 되었습니다");
        } catch (AuthorizationException e){
            log.error("AuthorizationException");
            httpServletResponse.sendError(HttpStatus.UNAUTHORIZED.value(), "권한이 없습니다");
        }
    }

    private boolean whiteListCheck(String uri){
        return PatternMatchUtils.simpleMatch(whiteListUris,uri);
    }

    private boolean isContainToken(HttpServletRequest request){
        String authorization = request.getHeader("Authorization");
        return authorization != null && authorization.startsWith("Bearer ");
    }

    private String getToken(HttpServletRequest request){
        String authorization = request.getHeader("Authorization");
        return authorization.substring(7);
    }

    private AuthenticateUser getAuthenticateUser(String token) throws JsonProcessingException {
        Claims claims = jwtProvider.getClaims(token);
        String authenticateUserJson = claims.get(VerifyUserFilter.AUTHENTICATE_USER, String.class);
        return objectMapper.readValue(authenticateUserJson, AuthenticateUser.class);
    }

    private void verifyAuthorization(String uri, AuthenticateUser user){
        if(PatternMatchUtils.simpleMatch("*/admin*",uri) && !user.getRoles().contains(Role.ADMIN)){
            throw new AuthorizationException();
        }
    }
}
```

일단 인가 처리가 필요하지 않은 요청에 대해서는 인가 처리를 하지 않도록  h2 database, login, refresh, register 관련한 uri를 whiteList 작성해 주었습니다. PatternMatchUtils를 이용해서 whiteList에 uri가 포함되어있는지 체크하고 만약 포함되어있으면 다음 필터로 넘어가줍니다. 그 다음 헤더에 토큰이 포함되어있는지 검증해주고 포험되어있지 않으면 UNAUTHORIZED errorCode를 보내줍니다. 이제 토큰에 대해 검증을 해주고 검증이 완료되면 토큰을 AuthenticateUser로 변환시켜줍니다. 그 다음 uri에 따른 권한 인가처리를 해주게 되는데 현재는 admin인 경우 Role.ADMIN 권한이 있는 경우에만 허용하도록 작성하였습니다.

### 마치면서

진짜 험난한 과정이었던 것 같습니다. 이 구조가 좋은 구조인지는 잘 모르겠지만 나름대로의 인증 및 인가처리에 대한 플로우를 이해할 수 있게 되었습니다. 이를 바탕으로 스프링 시큐리티를 공부하면 쉽게 이해할 수 있지않을까 싶은데요. 만들어 진걸 사용하는게 가장 베스트지만 한번쯤은 직접 만들어 보는것도 좋은 경험인것 같습니다. 여러모로 많은 트러블슈팅 경험하면서 많이 성장할 수 있었던 것 같습니다. 전체 코드는 아래 링크로 남겨드리겠습니다. 감사합니다.

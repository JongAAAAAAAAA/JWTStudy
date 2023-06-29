package com.example.jwtprac.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class TokenProvider implements InitializingBean { // 모든 속성이 BeanFactory에 의해 설정되면 반응해야 하는 빈에 의해 구현되는 인터페이스
    private static final String AUTHORITIES_KEY = "auth";
    private final String secret;
    private final long tokenValidityInMilliseconds;
    private Key key;

    public TokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds) {
        this.secret = secret;
        this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
    }

    @Override
    // 의존 관계가 끝나면 호출하겠다는 의미
    // 여기서 InitializingBean를 상속받고 이 메소드를 오버라이드한 이유는
    // TokenProvider Class가 Bean으로서 생성이 되고, 주입받은 후에 secret값을 Decode 하고, key 변수에 할당하기 위함.
    public void afterPropertiesSet(){
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public String createToken(Authentication authentication){ // Authentication : 인증 정보 저장 객체
        String authorities = authentication.getAuthorities().stream() // stream : 컬렉션에 저장된 요소들을 하나씩 순회하면서 처리함
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(",")); // , 로 구분

        long now = new Date().getTime();
        Date validity = new Date(now + this.tokenValidityInMilliseconds); // token의 expire time 설정

        return Jwts.builder() //JWT를 생성하기 위한 빌더 객체
                .setSubject(authentication.getName()) // 토큰의 주제를 나타내는 값
                .claim(AUTHORITIES_KEY, authorities) // 추가적인 클레임 설정, claim : payload에 포함되는 정보
                .signWith(key, SignatureAlgorithm.HS512) // JWT를 서명하기위해 Key, Algorithm 지정, 대칭키 사용
                .setExpiration(validity) // 만료 시간
                .compact(); // 마지막으로 JWT를 압축하고 서명하여 최종적인 JWT 문자열을 생성
    }

    // JWT 토큰을 복호화하여 토큰에 들어있는 정보를 꺼내는 코드
    // 토큰으로 클레임을 만들고 이를 이용해 유저 객체를 만들어서 최종적으로 authentication 객체를 리턴
    // 인증 정보 조회
    public Authentication getAuthentication(String token) {
        // 토큰 복호화 메소드
        Claims claims = Jwts
                .parserBuilder() // JWT를 파싱하기 위한 파서 빌더 객체를 생성
                .setSigningKey(key) // JWT를 검증하기 위해 사용할 서명 키를 설정
                .build() // JWT parser 객체 생성
                .parseClaimsJws(token) // 주어진 토큰을 해석하고 검증
                .getBody(); // 검증된 JWT의 Claim(paylod) 정보를 추출

        // 클레임 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // UserDetail 객체를 만듦.
        User principal = new User(claims.getSubject(), "", authorities);

        // 인증된 생성자인 Authentication 객체 생성
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    // 토큰의 유효성 검증을 수행하는 메서드
    public boolean validateToken(String token) {
        try {
            // 주어진 토큰을 해석하고 검증
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }


}

package com.example.jwtprac.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider implements InitializingBean { // 모든 속성이 BeanFactory에 의해 설정되면 반응해야 하는 빈에 의해 구현되는 인터페이스
    private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

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

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact();
    }


}

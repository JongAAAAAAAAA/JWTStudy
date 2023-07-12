package com.example.jwtprac.application;

import com.example.jwtprac.dao.MemberRepository;
import com.example.jwtprac.dto.LoginDTO;
import com.example.jwtprac.dto.MemberDTO;
import com.example.jwtprac.dto.TokenDTO;
import com.example.jwtprac.entity.Authority;
import com.example.jwtprac.entity.Member;
import com.example.jwtprac.jwt.JwtFilter;
import com.example.jwtprac.jwt.TokenProvider;
import com.example.jwtprac.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.ObjectUtils;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.Collections;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final TokenProvider tokenProvider;
    private final JwtFilter jwtFilter;
    private final StringRedisTemplate stringRedisTemplate;

    @Transactional
    // 회원가입 로직
    public Member signup(MemberDTO memberDTO) {
        // 이미 DB 안에 있는지 검사
        if (memberRepository.findOneWithAuthoritiesByUsername(memberDTO.getUsername()).orElse(null) != null) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        // 권한 정보 생성
        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        // 유저 생성
        Member member = Member.builder()
                .username(memberDTO.getUsername())
                .password(passwordEncoder.encode(memberDTO.getPassword()))
                .nickname(memberDTO.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        return memberRepository.save(member);
    }

    @Transactional(readOnly = true)
    public ResponseEntity<?> signin(@Valid LoginDTO loginDTO){
        // 로그인 정보로 AuthenticationToken 객체 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword());

        try{
            // 실제 검증 (사용자 비밀번호 체크)이 이루어지는 부분
            Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

            // 인증 정보를 기반으로 JWT 토큰 생성
            TokenDTO.TokenInfoDTO tokenInfoDTO = tokenProvider.createToken(authentication);

            // Refresh Token 을 Redis 에 저장 (expirationTime 설정을 통해 자동 삭제 처리)
            stringRedisTemplate.opsForValue().set("RT:" + authentication.getName(), tokenInfoDTO.getRefreshToken(),
                            tokenInfoDTO.getRefreshTokenExpiresIn(), TimeUnit.MILLISECONDS);

            // Access Token 을 Header 에 추가
            String accessToken = tokenInfoDTO.getAccessToken();
            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.remove(JwtFilter.AUTHORIZATION_HEADER); // Access Token Flush
//            httpHeaders.add("Content-Type", "application/json; charset=UTF-8");
            httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + accessToken);

            return new ResponseEntity<>(tokenInfoDTO, httpHeaders, HttpStatus.OK);
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>("아이디 또는 비밀번호가 일치하지 않습니다.", HttpStatus.BAD_REQUEST);
        }
    }

    @Transactional
    public ResponseEntity<?> logout(HttpServletRequest request){
        // Header 에서 Access Token 추출
        String accessToken = jwtFilter.resolveToken(request);

        // Access Token 검증
        if (!tokenProvider.validateToken(accessToken)) {
            log.info("access token: {}",accessToken);
            return new ResponseEntity<>("잘못된 요청입니다.", HttpStatus.BAD_REQUEST);
        }

        // Access Token 으로 Authentication 만듦
        Authentication authentication = tokenProvider.getAuthentication(accessToken);

        // Redis 에서 해당 username 으로 저장된 Refresh Token 이 있는지 여부를 확인 후 있을 경우 삭제
        if (stringRedisTemplate.opsForValue().get("RT:" + authentication.getName()) != null) {
            // Refresh Token 삭제
            stringRedisTemplate.delete("RT:" + authentication.getName());
        }

        // 해당 Access Token 유효시간 가지고 와서 BlackList 로 저장하기
        Long expiration = tokenProvider.getExpiration(accessToken);
        stringRedisTemplate.opsForValue()
                .set(accessToken, "logout", expiration, TimeUnit.MILLISECONDS);

        return new ResponseEntity<>("로그아웃 되었습니다.", HttpStatus.OK);
    }

    public ResponseEntity<?> reissue(HttpServletRequest request) {
        // Header 에서 Access Token 추출
        String accessToken = jwtFilter.resolveToken(request);

        // Access Token 으로 부터 Authentication 객체 생성
        Authentication authentication = tokenProvider.getAuthentication(accessToken);

        // Redis 에서 username 을 기반으로 저장된 Refresh Token 값을 가져옴
        String refreshToken = stringRedisTemplate.opsForValue().get("RT:" + authentication.getName());

        // 로그아웃되어 Redis 에 Refresh Token 이 삭제되어 존재하지 않는 경우 처리
        if(ObjectUtils.isEmpty(refreshToken)) {
            return new ResponseEntity<>("Refresh Token 정보가 존재하지 않습니다.", HttpStatus.BAD_REQUEST);
        }

        // Refresh Token 검증
        if (!tokenProvider.validateToken(refreshToken)) {
            return new ResponseEntity<>("Refresh Token 정보가 유효하지 않습니다.", HttpStatus.BAD_REQUEST);
        }

//        // Refresh Token 이 존재하지만 동일하지 않을 경우 처리
//        if(!refreshToken.equals(allTokenDTO.getRefreshToken())) {
//            return new ResponseEntity<>("Refresh Token 정보가 일치하지 않습니다.", HttpStatus.BAD_REQUEST);
//        }

        // 새로운 토큰 생성
        TokenDTO.TokenInfoDTO tokenInfoDTO = tokenProvider.createToken(authentication);

        // Refresh Token Redis 업데이트
        stringRedisTemplate.opsForValue()
                .set("RT:" + authentication.getName(), tokenInfoDTO.getRefreshToken(),
                        tokenInfoDTO.getRefreshTokenExpiresIn(), TimeUnit.MILLISECONDS);

        log.info("reissue!");
        return new ResponseEntity<>(tokenInfoDTO, HttpStatus.OK);
//        return new ResponseEntity<>(tokenInfoDTO, "Token 정보가 갱신되었습니다.", HttpStatus.OK);
    }

    @Transactional(readOnly = true)
    // username 을 이용해 유저, 권한정보 가져옴
    public Optional<Member> getUserWithAuthorities(String username) {
        return memberRepository.findOneWithAuthoritiesByUsername(username);
    }

//    @Transactional(readOnly = true)
//    // SecurityContext 에 저장된 CurrentUsername 에 해당하는 유저, 권한정보 가져옴
//    public Optional<Member> getMyUserWithAuthorities() {
//        return SecurityUtil.getCurrentUsername()
//                .flatMap(memberRepository::findOneWithAuthoritiesByUsername);
//    }
}
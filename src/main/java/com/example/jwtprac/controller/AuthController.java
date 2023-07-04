//package com.example.jwtprac.controller;
//
//import com.example.jwtprac.dto.LoginDTO;
//import com.example.jwtprac.dto.TokenDTO;
//import com.example.jwtprac.jwt.JwtFilter;
//import com.example.jwtprac.jwt.TokenProvider;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.RequestBody;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
//
//import javax.validation.Valid;
//
//@Slf4j
//@RestController
//@RequiredArgsConstructor
//@RequestMapping("/api")
//public class AuthController {
//    private final TokenProvider tokenProvider;
//    private final AuthenticationManagerBuilder authenticationManagerBuilder;
//
//    @PostMapping("/authenticate")
//    public ResponseEntity<TokenDTO> authorize(@Valid @RequestBody LoginDTO loginDTO) {
//        // 로그인 정보로 AuthenticationToken 객체 생성
//        UsernamePasswordAuthenticationToken authenticationToken =
//                new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword());
//
//        //AuthenticationManagerBuilder 가 호출되면서 CustomUserDetailService 클래스의 loadUserByUsername 이 실행됨.
//        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
//        SecurityContextHolder.getContext().setAuthentication(authentication); // SecurityContext에 인증 객체를 설정
//
//        // JWT 토큰을 생성
//        String jwt = tokenProvider.createToken(authentication);
//
//        HttpHeaders httpHeaders = new HttpHeaders();
//        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);
//
//        // 생성된 JWT 토큰을 HTTP 헤더에 넣고, TokenDTO를 통해 바디에도 넣고, 클라이언트에게 반환
//        return new ResponseEntity<>(new TokenDTO(jwt), httpHeaders, HttpStatus.OK);
//    }
//}

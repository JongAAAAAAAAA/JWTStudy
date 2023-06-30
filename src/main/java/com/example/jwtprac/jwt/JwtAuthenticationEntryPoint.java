package com.example.jwtprac.jwt;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
// 유효한 자격 증명이 제공되지 않았을 때에 대한 처리를 정의
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    // 유효한 자격 증명이 없는 경우, 자동으로 호출되는 메서드
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        // 유효한 자격 증명을 제공하지 않고 접근하려 할때 401
        // HTTP 응답 헤더에 401 Unauthorized 오류 코드를 설정
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}

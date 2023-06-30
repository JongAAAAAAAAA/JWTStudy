package com.example.jwtprac.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    public static final String AUTHORIZATION_HEADER = "Authorization";
    private final TokenProvider tokenProvider;

    @Override
    //실제 필터링 로직 작성 부분
    // JWT 토큰의 인증 정보를 SecurityContext에 저장
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        String jwt = resolveToken(request); // HttpServletRequest 객체에서 토큰을 추출
        String requestURI = request.getRequestURI(); // 현재 요청이 들어온 URI를 가져옴

        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) { // jwt가 존재하고 유효한 토큰인지 검증
            Authentication authentication = tokenProvider.getAuthentication(jwt); // Authentication 객체 생성
            SecurityContextHolder.getContext().setAuthentication(authentication); // SecurityContext에 저장
            // SecurityContext : Authentication 객체가 저장되는 보관소(전역)로 필요 시 언제든지 Authentication 객체를 꺼내어 쓸 수 있도록 제공되는 클래스
            // 이후 요청에서는 SecurityContext에서 인증된 사용자 정보를 조회하여 보안 및 인증 처리를 수행
            log.debug("Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), requestURI);
        } else {
            log.debug("유효한 JWT 토큰이 없습니다, uri: {}", requestURI);
        }

        filterChain.doFilter(request, response); // 다음 Filter로 요청을 전달
        // 모든 Filter를 거치면서 요청을 처리한다면, 최종적으로는 Servlet으로 요청이 전달
    }

    // 필터링을 하기 위한 토큰 정보를 얻는 메소드 - Request Header에서 토큰 정보 가져옴 -> Cookie에서 가져오는 방식으로 고쳐야함
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER); // Authorization 헤더 값을 가져옴.
        // Authorization 헤더 값 확인해보자
        log.info("bearerToken: {}", bearerToken);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) { // bearerToken 값이 null이 아니고, "Bearer "로 시작하는지 검사
            //Bearer 인증 스킴을 사용하고 있기 때문에, "Bearer " 이후부터 token 값이 시작되므로, bearerToken.substring(7)를 통해 "Bearer " 이후의 값만 가져옴
            return bearerToken.substring(7);
        }

        return null;
    }
}

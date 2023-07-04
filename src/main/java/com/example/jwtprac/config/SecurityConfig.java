package com.example.jwtprac.config;

import com.example.jwtprac.jwt.JwtAccessDeniedHandler;
import com.example.jwtprac.jwt.JwtAuthenticationEntryPoint;
import com.example.jwtprac.jwt.JwtSecurityConfig;
import com.example.jwtprac.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity // 기본적인 웹 보안 활성화
@EnableGlobalMethodSecurity(prePostEnabled = true) // @PreAuthorize 을 메소드 단위로 추가하기 위해 적용, @PreAuthorize 는 메서드 호출 전에 권한 검사를 수행
@RequiredArgsConstructor
public class SecurityConfig {
    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                /** 토큰 방식을 사용하기 때문에 csrf disable */
                .csrf().disable()

                /** 401, 403 Exception 핸들링 */
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                /** clickjacking 공격을 방지하는 X-Frame-Options 헤더 설정 */
                .and() // 보안 구성 체이닝(연결)
                .headers()
                .frameOptions()
                .sameOrigin()

                /** 세션 사용하지 않음 */
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                /** http 요청 접근 제한 */
                .and()
                .authorizeHttpRequests() // http 요청 접근 제한
                .antMatchers("/error").permitAll() // 에러 코드 확인용
                .antMatchers("/api/hello").permitAll() // "/api/hello" 의 접근은 인증없이 허용
                // 로그인, 회원가입은 토큰이 없는 상태로 요청이 들어오므로 permitAll
                .antMatchers("/api/authenticate").permitAll() // 토큰을 받기위한 로그인 api
                .antMatchers("/api/signup").permitAll() // 회원 가입을 위한 api
                .antMatchers("/api/signin").permitAll() // 로그인을 위한 api
                .anyRequest().authenticated() // 나머지 요청들은 모두 인증을 받아야 함

                /** JwtSecurityConfig 적용 */
                .and()
                .apply(new JwtSecurityConfig(tokenProvider));

        return http.build();
    }

}

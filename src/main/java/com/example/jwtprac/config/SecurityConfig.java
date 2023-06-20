package com.example.jwtprac.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity // 기본적인 웹 보안 활성화
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests() // http 요청 접근 제한
                .antMatchers("/api/hello").permitAll() // /api/hello 의 접근은 인증없이 허용
                .anyRequest().authenticated(); // 나머지 요청들은 모두 인증을 받아야 함

        return http.build();
    }

}

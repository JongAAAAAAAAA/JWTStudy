package com.example.jwtprac.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
// 토큰 정보를 Response 하기 위한 DTO
public class TokenDTO {
    private String token;
}
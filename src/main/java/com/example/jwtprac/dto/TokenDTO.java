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

    @Getter
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class TokenInfoDTO {
        private String grantType; // OAuth2 프로토콜에서 사용되는 필드
        private String accessToken;
        private Long accessTokenExpiresIn;
        private Long refreshTokenExpiresIn;
        private String refreshToken;
    }
}


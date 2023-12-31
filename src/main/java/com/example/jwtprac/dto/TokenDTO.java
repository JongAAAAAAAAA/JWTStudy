package com.example.jwtprac.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

// 토큰 정보를 Response 하기 위한 DTO
public class TokenDTO {
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

//    @Getter
//    @Builder
//    @AllArgsConstructor
//    @NoArgsConstructor
//    public static class AccessTokenDTO {
//        private String accessToken;
//    }

//    @Getter
//    @Builder
//    @AllArgsConstructor
//    @NoArgsConstructor
//    public static class AllTokenDTO {
//        private String accessToken;
//        private String refreshToken;
//    }
}


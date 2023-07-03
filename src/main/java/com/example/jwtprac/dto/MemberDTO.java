package com.example.jwtprac.dto;

import com.example.jwtprac.entity.Member;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class MemberDTO {
    @NotNull
    @Size(min = 3, max = 50) // Validation 검증을 위한 조건
    private String username;

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) // API 사용자가 이 객체를 통해 패스워드 값을 직접 변경할 수 없게함.
    @NotNull
    @Size(min = 3, max = 100)
    private String password;

    @NotNull
    @Size(min = 3, max = 50)
    private String nickname;

//    private Set<AuthorityDto> authorityDtoSet;
//
//    public static MemberDTO from(Member member) {
//        if(member == null) return null;
//
//        return MemberDTO.builder()
//                .username(member.getUsername())
//                .nickname(member.getNickname())
//                .authorityDtoSet(member.getAuthorities().stream()
//                        .map(authority -> AuthorityDto.builder().authorityName(authority.getAuthorityName()).build())
//                        .collect(Collectors.toSet()))
//                .build();
//    }
}

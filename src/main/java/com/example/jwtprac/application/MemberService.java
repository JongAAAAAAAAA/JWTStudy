package com.example.jwtprac.application;

import com.example.jwtprac.dao.MemberRepository;
import com.example.jwtprac.dto.MemberDTO;
import com.example.jwtprac.entity.Authority;
import com.example.jwtprac.entity.Member;
import com.example.jwtprac.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

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
    // username 을 이용해 유저, 권한정보 가져옴
    public Optional<Member> getUserWithAuthorities(String username) {
        return memberRepository.findOneWithAuthoritiesByUsername(username);
    }

    @Transactional(readOnly = true)
    // SecurityContext 에 저장된 CurrentUsername 에 해당하는 유저, 권한정보 가져옴
    public Optional<Member> getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername()
                .flatMap(memberRepository::findOneWithAuthoritiesByUsername);
    }
}
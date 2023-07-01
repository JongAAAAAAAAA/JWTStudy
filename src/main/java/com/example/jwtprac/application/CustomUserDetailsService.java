package com.example.jwtprac.application;

import com.example.jwtprac.dao.MemberRepository;
import com.example.jwtprac.entity.Member;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;

    /** 로그인 시 DB 에서 유저정보, 권한정보 가져옴. */
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) {
        log.info("Load By Username : " + username);
        return memberRepository.findOneWithAuthoritiesByUsername(username)
                .map(member -> createUser(username, member))
                .orElseThrow(() -> new UsernameNotFoundException(username + " -> 존재하지 않는 사용자입니다."));
    }

    /** Security User 객체를 생성한다. */
    private User createUser(String username, Member member) {
        if (!member.isActivated()) {
            throw new BadCredentialsException(username + " -> 활성화되어 있지 않습니다.");
        }

        // 활성화 상태라면 권한 정보와 username, password를 가지고 User 객체를 리턴해줌.
        List<GrantedAuthority> grantedAuthorities = member.getAuthorities().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
                .collect(Collectors.toList());

        return new User(member.getUsername(),
                member.getPassword(),
                grantedAuthorities);
    }
}

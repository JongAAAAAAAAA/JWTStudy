package com.example.jwtprac.controller;

import com.example.jwtprac.application.MemberService;
import com.example.jwtprac.dto.LoginDTO;
import com.example.jwtprac.dto.MemberDTO;
import com.example.jwtprac.dto.TokenDTO;
import com.example.jwtprac.entity.Member;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;

    @PostMapping("/signup")
    // ResponseEntity 는 HttpEntity 를 상속받는다. & Http Status(상태 코드) 등을 반환할 수 있다.
    // @Valid는 MemberDTO 에 걸려있는 유효성을 위배하는지 검사해줌.
    public ResponseEntity<Member> signup(@Valid @RequestBody MemberDTO memberDTO) {
        return ResponseEntity.ok(memberService.signup(memberDTO));
    }

    @PostMapping("/signin")
    // ResponseEntity 는 HttpEntity 를 상속받는다. & Http Status(상태 코드) 등을 반환할 수 있다.
    // @Valid는 MemberDTO 에 걸려있는 유효성을 위배하는지 검사해줌.
    public ResponseEntity<?> signin(@Valid @RequestBody LoginDTO loginDTO) {
        return ResponseEntity.ok(memberService.signin(loginDTO));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@Valid @RequestHeader(value = "Authorization") TokenDTO.AccessTokenDTO accessTokenDTO) {
        String accessToken = accessTokenDTO.getAccessToken();
        String sAccessToken = accessToken.substring(7);
        return ResponseEntity.ok(memberService.logout(sAccessToken));
    }
    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(@Valid @RequestHeader(value = "Authorization") TokenDTO.AccessTokenDTO accessTokenDTO) {
        String accessToken = accessTokenDTO.getAccessToken();
        String sAccessToken = accessToken.substring(7);
        return ResponseEntity.ok(memberService.reissue(sAccessToken));
    }

    @GetMapping("/member")
    @PreAuthorize("hasAnyRole('USER','ADMIN')") // @PreAuthorize 는 메서드 실행전에 주어진 인증 정보로 접근 제어를 수행
    public ResponseEntity<Member> getMyUserInfo() {
        return ResponseEntity.ok(memberService.getMyUserWithAuthorities().get());
    }

    @GetMapping("/member/{username}")
    @PreAuthorize("hasAnyRole('ADMIN')") // ADMIN 권한을 가진 사람만 호출할 수 있는 메서드
    public ResponseEntity<Member> getUserInfo(@PathVariable String username) {
        log.info(username);
        return ResponseEntity.ok(memberService.getUserWithAuthorities(username).get());
    }
}

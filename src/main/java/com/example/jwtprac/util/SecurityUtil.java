package com.example.jwtprac.util;

import com.example.jwtprac.error.NotSignInException;
import com.example.jwtprac.error.UnAuthorizedException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

@Slf4j
public class SecurityUtil {
//    // SecurityContext 에서 Authentication 객체를 이용해 username 을 리턴
//    public static Optional<String> getCurrentUsername() {
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//
//        if (authentication == null) {
//            log.debug("Security Context에 인증 정보가 없습니다.");
//            return Optional.empty();
//        }
//
//        String username = null;
//
//        // UserDetails 의 타입이 Object(UserDetails type) 이거나 String 일 수 있으므로 경우를 나눈다.
//        if (authentication.getPrincipal() instanceof UserDetails) {
//            UserDetails springSecurityUser = (UserDetails) authentication.getPrincipal();
//            username = springSecurityUser.getUsername();
//        } else if (authentication.getPrincipal() instanceof String) {
//            username = (String) authentication.getPrincipal();
//        }
//
//        return Optional.ofNullable(username);
//    }

    // 인증된 멤버의 pk 값을 확인하는 메서드
    public static Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        log.info("authentication:{}", authentication);

        if (authentication == null) { // authentication 에 인증 정보가 없는 경우
            throw new UnAuthorizedException();
        }

        if(authentication.getPrincipal().equals("anonymousUser")) { // 로그인 하지 않은 경우
            throw new NotSignInException();
        }

        String name = authentication.getName();
        Long userId = Long.valueOf(name);

        return userId;
    }
}

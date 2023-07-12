package com.example.jwtprac.error.handler;

import com.example.jwtprac.error.NotSignInException;
import com.example.jwtprac.error.UnAuthorizedException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice // 예외가 발생한 경우 해당 예외를 처리해주는 @ExceptionHandler 포함
public class GlobalExceptionHandler {
    @ExceptionHandler(UnAuthorizedException.class)
    protected final ResponseEntity<String> handleUnAuthorizedException(UnAuthorizedException e){
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
    }

    @ExceptionHandler(NotSignInException.class)
    protected final ResponseEntity<String> handleNotSignInException(NotSignInException e){
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
    }
}

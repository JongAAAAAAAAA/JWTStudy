package com.example.jwtprac.controller;

import com.example.jwtprac.util.SecurityUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api")
public class HelloController {
    @GetMapping("/hello")
    public ResponseEntity<String> hello(){
        log.info("test");
        return ResponseEntity.ok("hello");
    }

    @GetMapping("/hello/idTest")
    public ResponseEntity<Long> idTest(){
        Long currentUserId = SecurityUtil.getCurrentUserId();
        log.info("currentUserId: {}", currentUserId);
        return ResponseEntity.ok(currentUserId);
    }
}

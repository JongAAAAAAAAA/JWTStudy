package com.example.jwtprac;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

@SpringBootApplication
public class JwtPracApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtPracApplication.class, args);
    }

}

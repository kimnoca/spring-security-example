package com.example.securityexample.global.security.jwt;


import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class JwtException extends RuntimeException {
    private String message;
}

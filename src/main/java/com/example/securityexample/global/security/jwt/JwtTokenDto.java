package com.example.securityexample.global.security.jwt;


import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class JwtTokenDto {
    private String accessToken;
    private String refreshToken;
}

package com.example.securityexample.user.dto;


import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class RegisterRequestDto {
    private String username;
    private String password;
}

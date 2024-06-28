package com.example.securityexample.global.util;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum ErrorMessage {

    TOKEN_SIGNTURE_ERROR("잘못된 JWT 서명입니다."),
    JWT_EXPIRE_ERROR("만료된 JWT 토큰입니다."),
    UNSUPPORTED_TOKEN_ERROR("지원되지 않는 JWT 토큰입니다."),
    UNKNOWN_ERROR("토큰이 존재 하지 않습니다."),
    ALREADY_EXIST_USER_ERROR("이미 존재하는 email 입니다."),
    USER_NOT_FOUND_ERROR("존재하지 않는 유저 입니다."),
    BAD_CREDENTIALS_ERROR("옳지 않은 비밀번호 입니다.");

    private final String message;

}

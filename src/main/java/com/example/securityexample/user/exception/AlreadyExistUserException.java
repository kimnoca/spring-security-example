package com.example.securityexample.user.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class AlreadyExistUserException extends RuntimeException {
    private String message;
}

package com.example.securityexample.global.util;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class ErrorResponse {
    private int httpStatusCode;
    private String errorMessage;
}

package com.example.securityexample.global.security.handler;

import com.example.securityexample.global.util.ErrorMessage;
import com.example.securityexample.global.util.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;


// 401 handler
public class UserAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        String errorMessage = authException.getMessage();

        if (authException instanceof InsufficientAuthenticationException) {
            errorMessage = ErrorMessage.UNKNOWN_ERROR.getMessage();
        }

        ErrorResponse errorResponse = ErrorResponse.builder()
                .httpStatusCode(401)
                .errorMessage(errorMessage)
                .build();

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader("content-type", "application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));
        response.getWriter().flush();
        response.getWriter().close();
    }
}

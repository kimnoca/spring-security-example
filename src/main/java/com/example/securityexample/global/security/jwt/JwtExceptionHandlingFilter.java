package com.example.securityexample.global.security.jwt;

import com.example.securityexample.global.util.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtExceptionHandlingFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (JwtException ex) {
            String message = ex.getMessage();
            setResponse(response, message);
        }
    }

    private void setResponse(HttpServletResponse response, String errorMessage)
            throws RuntimeException, IOException {

        ErrorResponse errorResponse = ErrorResponse.builder()
                .httpStatusCode(401)
                .errorMessage(errorMessage)
                .build();

        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write(new ObjectMapper().writeValueAsString(errorResponse));
        response.getWriter().flush();
        response.getWriter().close();
    }
}


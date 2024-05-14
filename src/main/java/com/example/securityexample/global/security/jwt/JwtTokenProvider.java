package com.example.securityexample.global.security.jwt;


import com.example.securityexample.user.application.CustomUserDetailsService;
import com.example.securityexample.user.domain.MemberUserDetails;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenProvider {

    private final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);
    private final long accessTokenExpireSeconds;
    private final Key key;

    private final CustomUserDetailsService customUserDetailsService;

    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey,
                            @Value("${jwt.access-token-expire-seconds}") long accessTokenExpireSeconds,
                            CustomUserDetailsService customUserDetailsService) {
        this.accessTokenExpireSeconds = accessTokenExpireSeconds;
        this.customUserDetailsService = customUserDetailsService;
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public JwtTokenDto createToken(String email, String nickname) {
        long now = (new Date()).getTime();
        Date expireTime = new Date(now + this.accessTokenExpireSeconds);

        String accessToken = Jwts.builder()
                .setSubject(email)
                .claim("nickname", nickname)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(expireTime)
                .compact();

        String refreshToken = Jwts.builder()
                .setSubject(email)
                .signWith(key, SignatureAlgorithm.HS512)
                .claim("nickname", nickname)
                .setExpiration(expireTime)
                .compact();

        return JwtTokenDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public Authentication getAuthentication(String token) {
        String email = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();

        UserDetails userDetails = customUserDetailsService.loadUserByUsername(email);

        User principal = new User(email, "", userDetails.getAuthorities());

        return new UsernamePasswordAuthenticationToken(principal, "", userDetails.getAuthorities());
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {

            logger.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {

            logger.info("만료된 JWT 토큰입니다.");

        } catch (UnsupportedJwtException e) {
            logger.info("지원되지 않는 JWT 토큰입니다.");

        } catch (IllegalArgumentException e) {

            logger.info("JWT 토큰이 잘못되었습니다.");

        }
        return false;
    }
}



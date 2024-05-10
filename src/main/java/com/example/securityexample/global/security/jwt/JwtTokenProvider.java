package com.example.securityexample.global.security.jwt;


import com.example.securityexample.user.application.CustomUserDetailsService;
import com.example.securityexample.user.domain.MemberUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import org.springframework.stereotype.Component;

@Component
public class JwtTokenProvider {

    private final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);
    private final long accessTokenExpireSeconds;
    private final Key key;

    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey,
                            @Value("${jwt.access-token-expire-seconds}") long accessTokenExpireSeconds) {
        this.accessTokenExpireSeconds = accessTokenExpireSeconds;
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public JwtTokenDto createToken(Authentication authentication) {

        long now = (new Date()).getTime();
        Date expireTime = new Date(now + this.accessTokenExpireSeconds);

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        MemberUserDetails memberUserDetails = (MemberUserDetails) authentication.getPrincipal();
        String nickname = memberUserDetails.getMember().getNickname();

        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim("nickname", nickname)
                .claim("auth", authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(expireTime)
                .compact();

        String refreshToken = Jwts.builder()
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(expireTime)
                .compact();

        return JwtTokenDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, "", authorities);

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



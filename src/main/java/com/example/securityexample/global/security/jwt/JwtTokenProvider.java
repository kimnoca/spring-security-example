package com.example.securityexample.global.security.jwt;


import com.example.securityexample.global.util.ErrorMessage;
import com.example.securityexample.user.application.CustomUserDetailsService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import java.security.Key;
import java.util.Date;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenProvider {

    private final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);
    private final long tokenExpireSeconds;
    private final Key key;
    private final CustomUserDetailsService customUserDetailsService;

    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey,
                            @Value("${jwt.token-expire-seconds}") long accessTokenExpireSeconds,
                            CustomUserDetailsService customUserDetailsService) {
        this.tokenExpireSeconds = accessTokenExpireSeconds;
        this.customUserDetailsService = customUserDetailsService;
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public JwtTokenDto createToken(String email, String nickname) {
        long now = (new Date()).getTime();
        Date accessTokenExpireTime = new Date(now + this.tokenExpireSeconds);
        Date refreshTokenExpireTime = new Date(now + (tokenExpireSeconds * 2 * 30));

        String accessToken = Jwts.builder()
                .setSubject(email)
                .claim("nickname", nickname)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(accessTokenExpireTime)
                .compact();

        String refreshToken = Jwts.builder()
                .setSubject(email)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(refreshTokenExpireTime)
                .compact();

        return JwtTokenDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public Authentication getAuthentication(String token) {
        try {
            String email = getClaims(token).getSubject();
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(email);
            return new UsernamePasswordAuthenticationToken(userDetails, token, userDetails.getAuthorities());
        } catch (UsernameNotFoundException e) {
            throw new JwtException(ErrorMessage.USER_NOT_FOUND_ERROR.getMessage());
        }

    }

    public Claims getClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (SignatureException e) {
            logger.info("잘못된 JWT 서명입니다.");
            throw new JwtException(ErrorMessage.TOKEN_SIGNTURE_ERROR.getMessage());
        } catch (MalformedJwtException e) {
            logger.info("유효하지 않은 JWT 토큰");
            throw new JwtException("유효하지 않은 JWT 토큰");
        } catch (ExpiredJwtException e) {
            logger.info("만료된 JWT 토큰입니다.");
            throw new JwtException(ErrorMessage.JWT_EXPIRE_ERROR.getMessage());
        } catch (UnsupportedJwtException e) { // 이거랑
            logger.info("지원되지 않는 JWT 토큰입니다.");
            throw new JwtException(ErrorMessage.UNSUPPORTED_TOKEN_ERROR.getMessage());
        } catch (IllegalArgumentException e) { // 이거는 안잡히지?
            logger.info("JWT 토큰이 잘못되었습니다.");
            throw new JwtException(ErrorMessage.UNKNOWN_ERROR.getMessage());
        }
    }
}



package com.example.securityexample.user.application;


import com.example.securityexample.global.security.jwt.JwtTokenDto;
import com.example.securityexample.global.security.jwt.JwtTokenProvider;
import com.example.securityexample.user.dao.MemberRepository;
import com.example.securityexample.user.dao.RefreshTokenRepository;
import com.example.securityexample.user.domain.Member;
import com.example.securityexample.user.domain.RefreshToken;
import com.example.securityexample.user.dto.RefreshTokenDto;
import com.example.securityexample.user.type.Role;
import com.example.securityexample.user.dto.LoginRequestDto;
import com.example.securityexample.user.dto.RegisterRequestDto;

import io.jsonwebtoken.Claims;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class MemberService {

    private final JwtTokenProvider jwtTokenProvider;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;

    //TODO : Exception Global Handler 구현

    @Transactional
    public Member signUp(RegisterRequestDto registerRequestDto) {

        Member member = Member.builder()
                .email(registerRequestDto.getEmail())
                .password(passwordEncoder.encode(registerRequestDto.getPassword()))
                .nickname(registerRequestDto.getNickname())
                .role(Role.ROLE_USER)
                .build();

        return memberRepository.save(member);
    }

    public JwtTokenDto login(LoginRequestDto loginRequestDto) {
        Optional<Member> member = memberRepository.findByEmail(loginRequestDto.getEmail());

        if (member.isEmpty()) {
            throw new UsernameNotFoundException("존재 하지 않는 유저 입니다.");
        }

        if (!passwordEncoder.matches(loginRequestDto.getPassword(), member.get().getPassword())) {
            throw new BadCredentialsException("올바르지 않은 비밀번호 입니다.");
        }
        JwtTokenDto jwtTokenDto = jwtTokenProvider.createToken(loginRequestDto.getEmail(), member.get().getNickname());

        RefreshToken refreshToken = RefreshToken.builder()
                .token(jwtTokenDto.getRefreshToken())
                .userEmail(loginRequestDto.getEmail())
                .build();

        refreshTokenRepository.save(refreshToken);

        return jwtTokenDto;
    }

    public JwtTokenDto accessTokenReIssue(RefreshTokenDto refreshTokenDto) {

        Claims refreshToken = jwtTokenProvider.getClaims(refreshTokenDto.getRefreshToken());

        Optional<RefreshToken> userRefreshToken = refreshTokenRepository.findByUserEmail(refreshToken.getSubject());
        Optional<Member> member = memberRepository.findByEmail(refreshToken.getSubject());

        if (userRefreshToken.isEmpty() || member.isEmpty()) {
            throw new UsernameNotFoundException("존재 하지 않는 유저 입니다.");
        }

        System.out.println(refreshTokenDto.getRefreshToken() + "," + userRefreshToken.get().getToken());

        if (!jwtTokenProvider.validateToken(refreshTokenDto.getRefreshToken()) && !refreshTokenDto.getRefreshToken()
                .equals(userRefreshToken.get().getToken())) {
            throw new IllegalArgumentException("잘못된 refresh token 입니다.");
        }
        JwtTokenDto jwtTokenDto = jwtTokenProvider.createToken(refreshToken.getSubject(),
                member.get().getNickname());

        userRefreshToken.get().setToken(jwtTokenDto.getRefreshToken());

        return jwtTokenDto;
    }

}

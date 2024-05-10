package com.example.securityexample.user.application;


import com.example.securityexample.global.security.jwt.JwtTokenDto;
import com.example.securityexample.global.security.jwt.JwtTokenProvider;
import com.example.securityexample.user.dao.MemberRepository;
import com.example.securityexample.user.domain.Member;
import com.example.securityexample.user.type.Role;
import com.example.securityexample.user.dto.LoginRequestDto;
import com.example.securityexample.user.dto.RegisterRequestDto;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class MemberService {

    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    public JwtTokenDto login(LoginRequestDto loginRequestDto) {


        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                loginRequestDto.getEmail(),
                loginRequestDto.getPassword());

        Authentication authentication = authenticationManagerBuilder.getObject()
                .authenticate(authenticationToken); // CustomUserDetailsService 에 정의한 loadUserByUsername 실행
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return jwtTokenProvider.createToken(authentication);

    }

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
}

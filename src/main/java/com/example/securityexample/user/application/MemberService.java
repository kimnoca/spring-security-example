package com.example.securityexample.user.application;


import com.example.securityexample.global.security.jwt.JwtTokenDto;
import com.example.securityexample.global.security.jwt.JwtTokenProvider;
import com.example.securityexample.user.dao.MemberRepository;
import com.example.securityexample.user.domain.Member;
import com.example.securityexample.user.type.Role;
import com.example.securityexample.user.dto.LoginRequestDto;
import com.example.securityexample.user.dto.RegisterRequestDto;

import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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

    public JwtTokenDto login(LoginRequestDto loginRequestDto) {
        Optional<Member> member = memberRepository.findByEmail(loginRequestDto.getEmail());

        if (member.isEmpty()) {
            throw new UsernameNotFoundException("존재 하지 않는 유저 입니다.");
        }

        if (!passwordEncoder.matches(loginRequestDto.getPassword(), member.get().getPassword())) {
            throw new BadCredentialsException("올바르지 않은 비밀번호 입니다.");
        }

        return jwtTokenProvider.createToken(loginRequestDto.getEmail(), member.get().getNickname());
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

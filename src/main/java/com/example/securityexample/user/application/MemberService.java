package com.example.securityexample.user.application;


import com.example.securityexample.global.security.jwt.JwtTokenDto;
import com.example.securityexample.global.security.jwt.JwtTokenProvider;
import com.example.securityexample.global.util.ErrorMessage;
import com.example.securityexample.user.dao.MemberRepository;
import com.example.securityexample.user.dao.RefreshTokenRepository;
import com.example.securityexample.user.domain.Member;
import com.example.securityexample.user.domain.RefreshToken;
import com.example.securityexample.user.dto.LoginRequestDto;
import com.example.securityexample.user.dto.RefreshTokenDto;
import com.example.securityexample.user.dto.RegisterRequestDto;
import com.example.securityexample.user.exception.AlreadyExistUserException;
import com.example.securityexample.user.type.Role;
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

    public Member signUp(RegisterRequestDto registerRequestDto) {

        if (memberRepository.findByEmail(registerRequestDto.getEmail()).isPresent()) {
            throw new AlreadyExistUserException(ErrorMessage.ALREADY_EXIST_USER_ERROR.getMessage());
        }

        Member member = Member.builder().email(registerRequestDto.getEmail())
                .password(passwordEncoder.encode(registerRequestDto.getPassword()))
                .nickname(registerRequestDto.getNickname()).role(Role.ROLE_USER).build();

        return memberRepository.save(member);
    }

    public JwtTokenDto login(LoginRequestDto loginRequestDto) {

        Member member = memberRepository.findByEmail(loginRequestDto.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException(ErrorMessage.USER_NOT_FOUND_ERROR.getMessage()));

        if (!passwordEncoder.matches(loginRequestDto.getPassword(), member.getPassword())) {
            throw new BadCredentialsException(ErrorMessage.BAD_CREDENTIALS_ERROR.getMessage());
        }

        JwtTokenDto jwtTokenDto = jwtTokenProvider.createToken(loginRequestDto.getEmail(), member.getNickname());

        Optional<RefreshToken> optionalRefreshToken = refreshTokenRepository.findByUserEmail(
                loginRequestDto.getEmail());

        if (optionalRefreshToken.isPresent()) { // refresh token 이 있으면 update 하고 return
            optionalRefreshToken.get().updateRefreshToken(jwtTokenDto.getRefreshToken());
            return jwtTokenDto;
        }

        RefreshToken refreshToken = RefreshToken.builder().token(jwtTokenDto.getRefreshToken())
                .userEmail(loginRequestDto.getEmail()).build();

        refreshTokenRepository.save(refreshToken);

        return jwtTokenDto;
    }

    public JwtTokenDto accessTokenReIssue(RefreshTokenDto refreshTokenDto) {

        Claims refreshToken = jwtTokenProvider.getClaims(refreshTokenDto.getRefreshToken());

        if (!jwtTokenProvider.validateToken(refreshTokenDto.getRefreshToken())) {
            throw new IllegalArgumentException("잘못된 refresh token 입니다.");
        }

        RefreshToken userRefreshToken = refreshTokenRepository.findByUserEmail(refreshToken.getSubject())
                .orElseThrow(() -> new UsernameNotFoundException("존재 하지 않는 유저 입니다."));

        Member member = memberRepository.findByEmail(refreshToken.getSubject())
                .orElseThrow(() -> new UsernameNotFoundException("존재 하지 않는 유저 입니다."));

        if (!userRefreshToken.validateRefreshToken(refreshTokenDto.getRefreshToken())) {
            throw new IllegalArgumentException("잘못된 refresh token 입니다.");
        }

        JwtTokenDto jwtTokenDto = jwtTokenProvider.createToken(refreshToken.getSubject(), member.getNickname());

        userRefreshToken.updateRefreshToken(jwtTokenDto.getRefreshToken());

        return jwtTokenDto;
    }

}

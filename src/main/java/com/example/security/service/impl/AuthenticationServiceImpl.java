package com.example.security.service.impl;

import com.example.security.config.SecurityConfig;
import com.example.security.entity.User;
import com.example.security.enums.Role;
import com.example.security.enums.TokenType;
import com.example.security.model.AuthenticationResponse;
import com.example.security.model.SignInRequest;
import com.example.security.model.SignUpRequest;
import com.example.security.repository.UserRepository;
import com.example.security.service.AuthenticationService;
import com.example.security.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class AuthenticationServiceImpl implements AuthenticationService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecurityConfig securityConfig;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    public AuthenticationResponse register(SignUpRequest signUpRequest) {
        var user = User.builder()
                .email(signUpRequest.getEmail())
                .firstName(signUpRequest.getFirstName())
                .lastName(signUpRequest.getLastName())
                .password(securityConfig.passwordEncoder().encode(signUpRequest.getPassword()))
                .role(Role.USER)
                .validate_token(1)
                .build();

        String jwtToken = jwtService.generateToken(user);
        user = userRepository.save(user);
        return AuthenticationResponse.builder()
                .email(user.getEmail())
                .accessToken(jwtToken)
                .id(user.getId())
                .roles(user.getRole())
                .tokenType(TokenType.Bearer.name())
                .build();
    }

    @Override
    public AuthenticationResponse registerAdmin(SignUpRequest signUpRequest) {
        var user = User.builder()
                .email(signUpRequest.getEmail())
                .firstName(signUpRequest.getFirstName())
                .lastName(signUpRequest.getLastName())
                .password(securityConfig.passwordEncoder().encode(signUpRequest.getPassword()))
                .role(Role.ADMIN)
                .validate_token(1)
                .build();

        String jwtToken = jwtService.generateToken(user);
        user = userRepository.save(user);
        return AuthenticationResponse.builder()
                .email(user.getEmail())
                .accessToken(jwtToken)
                .id(user.getId())
                .roles(user.getRole())
                .tokenType(TokenType.Bearer.name())
                .build();
    }

    @Override
    public AuthenticationResponse login(SignInRequest signInRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(signInRequest.getEmail(), signInRequest.getPassword())
        );
        var user = userRepository.findByEmail(signInRequest.getEmail()).orElseThrow(() ->
                new IllegalArgumentException("Invalid Username or Password"));
        user.setValidate_token(1);
        userRepository.save(user);
        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .email(user.getEmail())
                .accessToken(jwtToken)
                .id(user.getId())
                .roles(user.getRole())
                .tokenType(TokenType.Bearer.name())
                .build();
    }

    @Override
    public HttpStatus logout(String token) {
        String user = jwtService.extractUsername(token);
        User user1 = userRepository.findByEmail(user).orElseThrow(() -> new IllegalArgumentException("Invalid Token"));
        if (jwtService.isTokenValid(token, user1) && user1.getValidate_token()==1 ) {
            user1.setValidate_token(0);
            userRepository.save(user1);
            return HttpStatus.OK;
        } else {
            return HttpStatus.BAD_REQUEST;
        }
    }
}

package com.example.security.controller;

import com.example.security.model.AuthenticationResponse;
import com.example.security.model.ErrorResponse;
import com.example.security.model.SignInRequest;
import com.example.security.model.SignUpRequest;
import com.example.security.repository.UserRepository;
import com.example.security.service.AuthenticationService;
import com.example.security.service.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RestController
@RequestMapping(path = "/auth")
@RequiredArgsConstructor
@CrossOrigin
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody SignUpRequest signUpRequest) {
        if (userRepository.findByEmail(signUpRequest.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().body(new ErrorResponse(HttpServletResponse.SC_BAD_REQUEST, "Email is exist! Please Login", Instant.now(), "Please Login!", ""));
        }
        AuthenticationResponse authenticationResponse = authenticationService.register(signUpRequest);
        ResponseCookie jwtCookie = jwtService.generateJwtCookie(authenticationResponse.getAccessToken());
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Authorization", authenticationResponse.getAccessToken());
        return ResponseEntity.ok().headers(httpHeaders).header(HttpHeaders.SET_COOKIE, jwtCookie.toString()).body(authenticationResponse);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody SignInRequest signInRequest) {
        if (userRepository.findByEmail(signInRequest.getEmail()).isEmpty()) {
            return ResponseEntity.badRequest().body(new ErrorResponse(HttpServletResponse.SC_BAD_REQUEST, "Email Id doesn't exist! Please Register", Instant.now(), "Please Register!", ""));
        }
        AuthenticationResponse authenticationResponse = authenticationService.login(signInRequest);
        ResponseCookie jwtCookie = jwtService.generateJwtCookie(authenticationResponse.getAccessToken());

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Authorization", authenticationResponse.getAccessToken());
        return ResponseEntity.ok().headers(httpHeaders).header(HttpHeaders.SET_COOKIE, jwtCookie.toString()).body(authenticationResponse);
    }

}

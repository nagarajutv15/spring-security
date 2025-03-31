package com.example.security.controller;

import com.example.security.entity.User;
import com.example.security.model.AuthenticationResponse;
import com.example.security.model.ErrorResponse;
import com.example.security.model.SignInRequest;
import com.example.security.model.SignUpRequest;
import com.example.security.repository.UserRepository;
import com.example.security.service.AuthenticationService;
import com.example.security.service.JwtService;
import com.example.security.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Optional;

@RestController
@RequestMapping(path = "/auth")
@RequiredArgsConstructor
@CrossOrigin
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final UserService userDetailsService;
    private final static String BEARER = "Bearer ";
    private final static String AUTHORIZATION = "Authorization";

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody SignUpRequest signUpRequest) {
        if (userRepository.findByEmail(signUpRequest.getEmail()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ErrorResponse(HttpServletResponse.SC_CONFLICT, "Email already exists! Please Login.", Instant.now(), "Please Login!", ""));
        }
        AuthenticationResponse authenticationResponse = authenticationService.register(signUpRequest);
        ResponseCookie jwtCookie = jwtService.generateJwtCookie(authenticationResponse.getAccessToken());
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(AUTHORIZATION, BEARER + authenticationResponse.getAccessToken());
        return ResponseEntity.status(HttpStatus.CREATED)
                .headers(httpHeaders)
                .body(authenticationResponse);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody SignInRequest signInRequest) {
        if (userRepository.findByEmail(signInRequest.getEmail()).isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorResponse(HttpServletResponse.SC_NOT_FOUND, "Email Id doesn't exist! Please Register.", Instant.now(), "Please Register!", ""));
        }
        AuthenticationResponse authenticationResponse = authenticationService.login(signInRequest);
        ResponseCookie jwtCookie = jwtService.generateJwtCookie(authenticationResponse.getAccessToken());

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(AUTHORIZATION, BEARER + authenticationResponse.getAccessToken());
        return ResponseEntity.ok().headers(httpHeaders).body(authenticationResponse);
    }

    @DeleteMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER)) {
            String jwtToken = authorizationHeader.substring(7);
            HttpStatus status = authenticationService.logout(jwtToken);
            if (status.equals(HttpStatus.OK)) {
                return ResponseEntity.status(HttpStatus.OK).build();
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Logout failed.");
            }
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Authorization header missing.");
    }

    @GetMapping("/validate")
    public ResponseEntity<Void> validate(@RequestHeader("Authorization") String authorizationHeader) {
        HttpHeaders httpHeaders = new HttpHeaders();

        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER)) {
            String jwtToken = authorizationHeader.substring(7);
            String user = jwtService.extractUsername(jwtToken);
            UserDetails userDetails = userDetailsService.userDetailsService().loadUserByUsername(user);
            boolean isValid = jwtService.isTokenValid(jwtToken, userDetails);
            Optional<User> user1 = userRepository.findByEmail(user);
            if (isValid && user1.get().isValidate_token()) {
                httpHeaders.add(AUTHORIZATION, jwtToken);
                httpHeaders.add("USER", user);
                return ResponseEntity.ok().headers(httpHeaders).build();
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).headers(httpHeaders).build();
            }
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).headers(httpHeaders).build();
    }


}


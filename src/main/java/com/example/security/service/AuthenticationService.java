package com.example.security.service;

import com.example.security.model.AuthenticationResponse;
import com.example.security.model.SignInRequest;
import com.example.security.model.SignUpRequest;
import org.springframework.http.HttpStatus;

public interface AuthenticationService {

    AuthenticationResponse register(SignUpRequest signUpRequest);

    AuthenticationResponse registerAdmin(SignUpRequest signUpRequest);

    AuthenticationResponse login(SignInRequest signInRequest);

    HttpStatus logout(String token);
}

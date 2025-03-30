package com.example.security.model;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class SignInRequest {

    @NotEmpty(message = "Email can't be empty")
    private String email;

    @NotEmpty(message = "Password can't be empty")
    private String password;
}

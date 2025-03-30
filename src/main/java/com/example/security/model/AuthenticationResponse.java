package com.example.security.model;

import com.example.security.enums.Role;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {

    private long id;
    private String email;
    private Role roles;

    @JsonIgnore
    private String accessToken;
    @JsonIgnore
    private String tokenType;
}

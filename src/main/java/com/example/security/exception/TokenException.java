package com.example.security.exception;

import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus
public class TokenException extends RuntimeException{
    public TokenException(String message, String jwtTokenIsExpired) {
        super(message);
    }
}

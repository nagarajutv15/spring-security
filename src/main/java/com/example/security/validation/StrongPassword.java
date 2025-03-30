package com.example.security.validation;

import java.lang.annotation.*;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Target({ElementType.METHOD,ElementType.FIELD})
@Constraint(validatedBy = StrongPasswordValidator.class)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface StrongPassword {

    String message() default "Password must be 8 characters long and contain at least one uppercase letter, one lowercase letter, one number and one special character";

    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}


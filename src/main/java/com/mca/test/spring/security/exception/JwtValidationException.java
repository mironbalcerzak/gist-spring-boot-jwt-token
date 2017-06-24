package com.mca.test.spring.security.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Exception type for JWT validation failures.
 */
public class JwtValidationException extends AuthenticationException {

    public JwtValidationException(String msg, Throwable t) {
        super(msg, t);
    }

}

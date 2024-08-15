package com.gethealthy.authenticationservice.exception;

public class TokenExpiredException extends RuntimeException{
    public TokenExpiredException() {
        super("The provided token is expired");

    }
}

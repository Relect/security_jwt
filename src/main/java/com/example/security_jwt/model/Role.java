package com.example.security_jwt.model;

import org.springframework.security.core.GrantedAuthority;

public enum Role implements GrantedAuthority {
    USER,
    MODERATOR,
    SUPER_ADMIN;

    @Override
    public String getAuthority() {
        return name();
    }
}

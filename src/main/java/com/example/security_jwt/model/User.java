package com.example.security_jwt.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "users")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    private int failedLoginAttempts = 0;
    @Enumerated(EnumType.STRING)
    private Role role;
    private boolean isAccountNonLocked;

    public User(String username, String password, int failedLoginAttempts, Role role, boolean isAccountNonLocked) {
        this.username = username;
        this.password = password;
        this.failedLoginAttempts = failedLoginAttempts;
        this.role = role;
        this.isAccountNonLocked = isAccountNonLocked;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(role);
    }

    @Override
    public boolean isAccountNonLocked() {
        return isAccountNonLocked;
    }
}

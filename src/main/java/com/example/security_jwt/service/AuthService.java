package com.example.security_jwt.service;

import com.example.security_jwt.dto.ReqRes;
import com.example.security_jwt.model.User;
import com.example.security_jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JWTUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public ReqRes signUp(ReqRes regitstrantRequest) {
        ReqRes resp = new ReqRes();
        try {
            User user = new User();
            user.setUsername(regitstrantRequest.getUsername());
            user.setPassword(passwordEncoder.encode(regitstrantRequest.getPassword()));
            user.setRole(regitstrantRequest.getRole());
            user.setAccountNonLocked(true);
            user.setFailedLoginAttempts(0);
            User result = userRepository.save(user);
            if (result != null && user.getId() > 0) {
                resp.setUser(result);
                resp.setMessage("Пользователь успешно сохранён");
                resp.setStatusCode(200);
            }
        } catch (Exception e) {
            resp.setStatusCode(500);
            resp.setError(e.getMessage());
        }
        return resp;
    }

    public ReqRes signIn(ReqRes signinRequest) {
        ReqRes response = new ReqRes();

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    signinRequest.getUsername(), signinRequest.getPassword()));
            var user = userRepository.findByUsername(signinRequest.getUsername()).orElseThrow();
            System.out.println("USER IS: " + user);
            var jwt = jwtUtils.generateToken(user);
            var refreshToken = jwtUtils.generateRefreshToken(new HashMap<>(), user);
            response.setStatusCode(200);
            response.setToken(jwt);
            response.setRefreshToken(refreshToken);
            response.setExpirationTime("24Hr");
            response.setMessage("Successfully Signed In");
        } catch (AuthenticationException e) {
            var user1 = userRepository.findByUsername(signinRequest.getUsername()).orElse(null);
            if (user1 != null && user1.isAccountNonLocked()) {
                int attemp = user1.getFailedLoginAttempts();
                if (attemp < 5 ) {
                    attemp++;
                    user1.setFailedLoginAttempts(attemp);
                    userRepository.save(user1);
                } else {
                    user1.setAccountNonLocked(false);
                    userRepository.save(user1);
                }
            }
            response.setStatusCode(403);
            response.setError(e.getMessage());
        } catch (Exception e){
            response.setStatusCode(500);
            response.setError(e.getMessage());
        }
        return response;
    }

    public ReqRes refreshToken(ReqRes refreshTokenReqiest){
        ReqRes response = new ReqRes();
        String username = jwtUtils.extractUsername(refreshTokenReqiest.getToken());
        User users = userRepository.findByUsername(username).orElseThrow();
        if (jwtUtils.isTokenValid(refreshTokenReqiest.getToken(), users)) {
            var jwt = jwtUtils.generateToken(users);
            response.setStatusCode(200);
            response.setToken(jwt);
            response.setRefreshToken(refreshTokenReqiest.getToken());
            response.setExpirationTime("24Hr");
            response.setMessage("Successfully Refreshed Token");
        }
        response.setStatusCode(500);
        return response;
    }
}

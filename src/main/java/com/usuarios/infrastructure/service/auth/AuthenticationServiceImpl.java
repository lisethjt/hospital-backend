package com.usuarios.infrastructure.service.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import com.usuarios.application.usercase.AuthenticationService;
import com.usuarios.infrastructure.payload.auth.LoginRequest;
import com.usuarios.infrastructure.payload.auth.LoginResponse;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {

	private final AuthenticationManager authenticationManager;

	public AuthenticationServiceImpl(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Override
	public LoginResponse authenticate(LoginRequest loginRequest) {
		 // Autenticamos al usuario
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                		loginRequest.getEmail(),
                		loginRequest.getPassword()
                )
        );
        
        String token = JwtHelper.generateToken(loginRequest.getEmail());        
		return LoginResponse.builder()
				.accessToken(token)				
				.build();
	}
}
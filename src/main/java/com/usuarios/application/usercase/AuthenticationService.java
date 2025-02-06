package com.usuarios.application.usercase;

import com.usuarios.infrastructure.payload.auth.LoginRequest;
import com.usuarios.infrastructure.payload.auth.LoginResponse;

public interface AuthenticationService {
	
	LoginResponse authenticate(LoginRequest loginRequest);
}
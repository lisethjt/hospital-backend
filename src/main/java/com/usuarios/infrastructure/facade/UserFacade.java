package com.usuarios.infrastructure.facade;

import com.usuarios.infrastructure.payload.UserListResponse;
import com.usuarios.infrastructure.payload.UserRequest;
import com.usuarios.infrastructure.payload.UserResponse;

public interface UserFacade {

	UserResponse add(UserRequest user);

	UserListResponse findAll();

	UserResponse update(UserRequest user, Long id);

	void deleteUser(Long id);
}
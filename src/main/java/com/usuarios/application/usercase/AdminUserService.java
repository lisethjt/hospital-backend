package com.usuarios.application.usercase;

import java.util.List;

import com.usuarios.domain.User;

public interface AdminUserService {

	User add(User user);

	List<User> findAll();

	User update(User user, Long id);

	void deleteUser(Long id);
}
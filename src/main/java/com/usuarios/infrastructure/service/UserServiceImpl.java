package com.usuarios.infrastructure.service;

import java.util.List;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.usuarios.application.port.UserRepositoryPort;
import com.usuarios.application.usercase.AdminUserService;
import com.usuarios.domain.User;

@Service
public class UserServiceImpl implements AdminUserService {

	private UserRepositoryPort userRepositoryPort;
	private PasswordEncoder passwordEncoder;

	public UserServiceImpl(UserRepositoryPort userRepositoryPort, PasswordEncoder passwordEncoder) {
		this.userRepositoryPort = userRepositoryPort;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public User add(User user) {
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return this.userRepositoryPort.add(user);
	}

	@Override
	public List<User> findAll() {
		return this.userRepositoryPort.findAll();
	}

	@Override
	public User update(User user, Long id) {
		return this.userRepositoryPort.update(user, id);
	}

	@Override
	public void deleteUser(Long id) {
		this.userRepositoryPort.deleteUser(id);
	}
}
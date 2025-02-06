package com.usuarios.infrastructure.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.usuarios.infrastructure.entities.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

	Optional<UserEntity> findByName(String name);

	Optional<UserEntity> findByEmail(String email);
}
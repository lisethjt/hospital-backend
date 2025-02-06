package com.usuarios.infrastructure.mapper;

import com.usuarios.domain.User;
import com.usuarios.infrastructure.entities.UserEntity;

public final class UserDboMapper {

	
	public static UserEntity toUserEntity(User user) {
		return UserEntity.builder()				
				.name(user.getName())
				.password(user.getPassword())
				.email(user.getEmail())
				.image(user.getImage())
				.role(user.getRole())
				.google(user.getGoogle())
				.build();
	}
	
	public static User toUser(UserEntity user) {
		return User.builder()				
				.name(user.getName())
				.password(user.getPassword())
				.email(user.getEmail())
				.image(user.getImage())
				.role(user.getRole())
				.google(user.getGoogle())
				.build();
	}
}
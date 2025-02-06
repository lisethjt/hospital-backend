package com.usuarios.infrastructure.mapper;

import com.usuarios.domain.User;
import com.usuarios.infrastructure.payload.UserDto;
import com.usuarios.infrastructure.payload.UserRequest;

public final class UserDtoMapper {

	public static User toUser(UserRequest user) {
		return User.builder()				
				.name(user.getName())
				.password(user.getPassword())
				.email(user.getEmail())
				.image(user.getImage())
				.role(user.getRole())
				.google(user.getGoogle())
				.build();
	}
	
	public static UserDto toUserDto(User user) {
		return UserDto.builder()				
				.name(user.getName())
				.password(user.getPassword())
				.email(user.getEmail())
				.image(user.getImage())
				.role(user.getRole())
				.google(user.getGoogle())
				.build();
	}
	
}
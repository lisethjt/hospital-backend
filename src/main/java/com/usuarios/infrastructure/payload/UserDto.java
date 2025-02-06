package com.usuarios.infrastructure.payload;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {

	
	private String name;
	private String password;
	private String email;
	private String image;
	private String role;
	private Boolean google;
}
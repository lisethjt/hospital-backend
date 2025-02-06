package com.usuarios.domain;

import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

	private String name;
	private String password;
	private String email;
	private String image;
	private String role;
	private Boolean google;	
	private Instant date;

	@Override
	public String toString() {
		return "UserEntity [name=" + name + ", password=" + password + ", email=" + email + ", image="
				+ image + ", role=" + role + ", google=" + google + ", date=" + date + "]";
	}
}
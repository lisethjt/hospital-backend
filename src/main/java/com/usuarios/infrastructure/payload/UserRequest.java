package com.usuarios.infrastructure.payload;

import org.hibernate.validator.constraints.Length;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserRequest {

	@NotBlank(message = "El nombre no puede estar vacío")
	private String name;
	@NotBlank(message = "La contraseña no puede estar vacía")
	@Length(min = 6, message = "La contraseña debe tener al menos 6 caracteres")
	private String password;
	@Email(message = "El email debe ser válido")
	private String email;
	private String image;
	private String role;
	private Boolean google;
}
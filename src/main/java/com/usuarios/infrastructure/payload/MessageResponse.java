package com.usuarios.infrastructure.payload;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class MessageResponse {

	private String code;
	private String message;

	@Override
	public String toString() {
		return "MessageResponse [code=" + code + ", message=" + message + "]";
	}
}
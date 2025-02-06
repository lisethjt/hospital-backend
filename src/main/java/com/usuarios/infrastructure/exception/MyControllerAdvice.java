package com.usuarios.infrastructure.exception;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class MyControllerAdvice {

	@ExceptionHandler(UserException.class)
	public ResponseEntity<String> handleEmptyInput(UserException emptyInputException) {
		return new ResponseEntity<String>(emptyInputException.getErrorMessage(), emptyInputException.getErrorCode());
	}
	
	@ExceptionHandler(UsernameNotFoundException.class)
	public ResponseEntity<String> handleEmptyInput(UsernameNotFoundException emptyInputException) {
		return new ResponseEntity<String>(emptyInputException.getMessage(), HttpStatusCode.valueOf(10));
	}
}
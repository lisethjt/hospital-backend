package com.usuarios.infrastructure.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.usuarios.infrastructure.facade.UserFacade;
import com.usuarios.infrastructure.payload.UserListResponse;
import com.usuarios.infrastructure.payload.UserRequest;
import com.usuarios.infrastructure.payload.UserResponse;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping(value = "users")
public class UserController {

	private UserFacade userFacade;

	public UserController(UserFacade userFacade) {
		this.userFacade = userFacade;
	}

	@PostMapping("/add")
	public ResponseEntity<UserResponse> addUser(@RequestBody UserRequest userRequest) {
		return ResponseEntity.ok().body(this.userFacade.add(userRequest));
	}

	@GetMapping("/all")
	public ResponseEntity<UserListResponse> allUsers() {
		return ResponseEntity.ok().body(this.userFacade.findAll());
	}

	@PutMapping("/update/{userId}")
	public ResponseEntity<UserResponse> updateUser(@RequestBody UserRequest userRequest,
			@PathVariable("userId") Long userId) {
		return ResponseEntity.ok().body(this.userFacade.update(userRequest, userId));
	}

	@DeleteMapping("/delete/{userId}")
	public ResponseEntity<UserResponse> deleteUser(@PathVariable("userId") Long userId) {
		return null;
	}
}
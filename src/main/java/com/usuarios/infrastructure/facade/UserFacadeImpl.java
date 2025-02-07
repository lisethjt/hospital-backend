package com.usuarios.infrastructure.facade;

import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.usuarios.application.usercase.AdminUserService;
import com.usuarios.domain.User;
import com.usuarios.infrastructure.mapper.UserDtoMapper;
import com.usuarios.infrastructure.payload.MessageResponse;
import com.usuarios.infrastructure.payload.UserListResponse;
import com.usuarios.infrastructure.payload.UserRequest;
import com.usuarios.infrastructure.payload.UserResponse;
import com.usuarios.infrastructure.service.auth.JwtHelper;

@Service
public class UserFacadeImpl implements UserFacade {

	private AdminUserService userService;

	public UserFacadeImpl(AdminUserService userService) {
		this.userService = userService;
	}

	@Override
	public UserResponse add(UserRequest user) {
		UserResponse userResponse = new UserResponse();
		MessageResponse messageResponse = new MessageResponse();
		messageResponse.setCode("201");
		messageResponse.setMessage("Exito");
		
		User userObj= userService.add(UserDtoMapper.toUser(user));
		if(userObj == null) {
			messageResponse.setCode("400");
			messageResponse.setMessage("El usuario no pudo ser registrado");
			userResponse.setMessage(messageResponse);
			return userResponse;
		}
		
		userResponse.setUser(UserDtoMapper.toUserDto(userObj));
		userResponse.setMessage(messageResponse);
		userResponse.setToken(JwtHelper.generateToken(user.getEmail()));
		return userResponse;
	}

	@Override
	public UserListResponse findAll() {
		UserListResponse userResponse = new UserListResponse();
		MessageResponse messageResponse = new MessageResponse();
		messageResponse.setCode("200");
		messageResponse.setMessage("Exito");
		userResponse.setUsers(this.userService.findAll()
                					.stream()
                					.map(UserDtoMapper::toUserDto)
                					.collect(Collectors.toList()));
		userResponse.setMessage(messageResponse);		
		return userResponse;
	}

	@Override
	public UserResponse update(UserRequest user, Long id) {
		UserResponse userResponse = new UserResponse();
		MessageResponse messageResponse = new MessageResponse();
		messageResponse.setCode("200");
		messageResponse.setMessage("Exito");
		userResponse.setUser(UserDtoMapper.toUserDto(this.userService.update(UserDtoMapper.toUser(user), id)));
		userResponse.setMessage(messageResponse);
		return userResponse;
	}

	@Override
	public void deleteUser(Long id) {
		// TODO Auto-generated method stub
	}

}

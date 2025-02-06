package com.usuarios.infrastructure.repository;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Repository;

import com.usuarios.application.port.UserRepositoryPort;
import com.usuarios.domain.User;
import com.usuarios.infrastructure.entities.UserEntity;
import com.usuarios.infrastructure.exception.UserException;
import com.usuarios.infrastructure.mapper.UserDboMapper;
import com.usuarios.infrastructure.util.UserConstant;

@Repository
public class UserRepositoryPortImpl implements UserRepositoryPort {

	private UserRepository userRespository;

	public UserRepositoryPortImpl(UserRepository userRespository) {
		this.userRespository = userRespository;
	}

	@Override
	public User add(User user) {
		User userObj = null;
		Optional<UserEntity> userList = this.userRespository.findByName(user.getName());
		if(userList.isPresent()) {
			userList.orElseThrow(
				() -> new UserException(HttpStatus.BAD_REQUEST, UserConstant.USER_FOUND_MESSAGE_ERROR ));
		}else {
			userObj = UserDboMapper.toUser(this.userRespository.save(UserDboMapper.toUserEntity(user)));
		}
		
		return userObj; 
	}

	@Override
	public List<User> findAll() {		
		return this.userRespository.findAll()
				.stream()
				.map(UserDboMapper::toUser)
				.collect(Collectors.toList());
	}

	@Override
	public User update(User user, Long id) {
		Optional<UserEntity> userList = this.userRespository.findById(id);
		if(userList.isPresent()) {
			userList.orElseThrow(
					() -> new UserException(HttpStatus.BAD_REQUEST, UserConstant.USER_NOT_FOUND_MESSAGE_ERROR ));
		}
		
		UserEntity userEntity = userList.get();
		userEntity.setImage(user.getImage());
		userEntity.setRole(user.getRole());
		return UserDboMapper.toUser(this.userRespository.save(userEntity));
	}

	@Override
	public void deleteUser(Long id) {
		this.userRespository.deleteById(id);
	}
}
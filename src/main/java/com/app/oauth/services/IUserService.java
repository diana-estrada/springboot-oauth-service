package com.app.oauth.services;

import com.app.userscommons.models.User;

public interface IUserService {
	
	public User findByUsername(String username);
	
	public User update(User user, Long id);

}

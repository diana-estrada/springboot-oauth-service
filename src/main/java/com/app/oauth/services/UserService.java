package com.app.oauth.services;

import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.app.oauth.clients.UserFeignClient;

import brave.Tracer;
import feign.FeignException;

@Service
public class UserService implements UserDetailsService, IUserService {

	private Logger log = LoggerFactory.getLogger(UserService.class);

	@Autowired
	private UserFeignClient client;
	
	@Autowired
	private Tracer tracer;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		try {
			com.app.userscommons.models.User user = client.findByUsername(username);

			List<GrantedAuthority> authorities = user.getRoles().stream()
					.map(role -> new SimpleGrantedAuthority(role.getName()))
					.peek(authority -> log.info("Role: " + authority.getAuthority())).collect(Collectors.toList());

			log.info("Usuario Autenticado: " + username);

			return new User(user.getUsername(), user.getPasssword(), user.getEnabled(), true, true, true, authorities);
		} catch (FeignException e) {
			String msg = "Error e login, no existe el username" + username + "en el sistema";
			log.info(msg);
			tracer.currentSpan().tag("error.mensaje", msg + ": " + e.getMessage());
			throw new UsernameNotFoundException("Error e login, no existe el username" + username + "en el sistema");
		}
	}

	@Override
	public com.app.userscommons.models.User findByUsername(String username) {

		return client.findByUsername(username);
	}

	@Override
	public com.app.userscommons.models.User update(com.app.userscommons.models.User user, Long id) {

		return client.update(user, id);
	}

}

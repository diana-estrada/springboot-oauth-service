package com.app.oauth.security.event;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.app.oauth.services.IUserService;
import com.app.userscommons.models.User;

import brave.Tracer;
import feign.FeignException;

@Component
public class AuthenticationSuccessErrorHandler implements AuthenticationEventPublisher {

	private Logger log = LoggerFactory.getLogger(AuthenticationSuccessErrorHandler.class);

	@Autowired
	private IUserService userService;
	
	@Autowired
	private Tracer tracer;

	@Override
	public void publishAuthenticationSuccess(Authentication authentication) {
		// UserDetails userInfo = (UserDetails)authentication.getPrincipal();
		String username = ((UserDetails) authentication.getPrincipal()).getUsername();
		System.out.println("Success Login*******: " + username);

		// log.info("Success Login###########: " +
		// ((UserDetails)authentication.getPrincipal()).getUsername());

		try {
			
			User user = userService.findByUsername(username);

			if (user.getTries() != null && user.getTries() > 0) {
				user.setTries(0);
				userService.update(user, user.getId());
			}
		} catch (FeignException e) {
			log.error("ERRO ENTRAMOS EN SUCESS OPCION");
		}
	}

	@Override
	public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
		log.error("Error en el login: " + exception.getMessage());
		System.out.println("Error en el login: " + exception.getMessage());

		try {
			StringBuilder errors = new StringBuilder();
			errors.append("Error en el login: " + exception.getMessage());
			User user = userService.findByUsername(authentication.getName());
			if (user.getTries() == null) {
				user.setTries(0);
			}

			log.info("Intentos actual: " + user.getTries());

			user.setTries(user.getTries() + 1);

			log.info("Intentos despues: " + user.getTries());
			errors.append("Intentos del login: " + user.getTries());
			if (user.getTries() >= 3) {
				log.error(String.format("El usuario %s deshabilitado por maximo de intentos", user.getUsername()));
				errors.append("------- El usuario deshabilitado por maximo de intentos");
				user.setEnabled(false);
			}

			userService.update(user, user.getId());
			tracer.currentSpan().tag("error.mensaje", errors.toString());
		} catch (FeignException e) {
			log.error(String.format("El usuario %s no existe en el sistema.", authentication.getName()));
		}

	}

}

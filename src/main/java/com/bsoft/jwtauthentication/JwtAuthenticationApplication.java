package com.bsoft.jwtauthentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.bsoft.jwtauthentication.configs.security.AuthEntryPointJwt;

@SpringBootApplication
public class JwtAuthenticationApplication {
	public static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

	public static void main(String[] args) {
		SpringApplication.run(JwtAuthenticationApplication.class, args);
	}

}

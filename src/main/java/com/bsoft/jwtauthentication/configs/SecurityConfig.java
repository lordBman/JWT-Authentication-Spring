package com.bsoft.jwtauthentication.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.bsoft.jwtauthentication.JwtAuthenticationApplication;
import com.bsoft.jwtauthentication.configs.security.AuthEntryPointJwt;
import com.bsoft.jwtauthentication.configs.security.AuthenticationFilter;
import com.bsoft.jwtauthentication.services.UserService;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    AuthEntryPointJwt authEntryPointJwt;

    @Autowired
    AuthenticationFilter authenticationFilter;

    @Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

    @Autowired
	UserService userDetailsService;

    @Bean
	AuthenticationManager authenticationManager() {
		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userDetailsService);
		authenticationProvider.setPasswordEncoder(passwordEncoder());

        JwtAuthenticationApplication.logger.info("AuthenticationManager has been initialized");

		return new ProviderManager(authenticationProvider);
	}

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((auth) -> {
            auth.requestMatchers("/users/**").authenticated().anyRequest().permitAll();
        }).exceptionHandling(exception -> {
            exception.authenticationEntryPoint(authEntryPointJwt);
        }).sessionManagement(management -> {
            management.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        });
        
        http.authenticationManager(authenticationManager());
        http.addFilterBefore(authenticationFilter , UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
}

package com.bsoft.jwtauthentication.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.bsoft.jwtauthentication.configs.security.AuthEntryPointJwt;
import com.bsoft.jwtauthentication.configs.security.UnauthorizedHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UnauthorizedHandler unauthorizedHandler;

    @Autowired
    AuthEntryPointJwt authEntryPointJwt;

    @Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

    @Bean
	UserDetailsService userDetailsService() {
		UserDetails userDetails = User.builder().username("user")
			.password("password")
			.roles("USER")
			.build();

		return new InMemoryUserDetailsManager(userDetails);
	}

    @Bean
	AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userDetailsService);
		authenticationProvider.setPasswordEncoder(passwordEncoder);

		return new ProviderManager(authenticationProvider);
	}

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((auth)->{
            auth.requestMatchers("/users/**").authenticated().anyRequest().permitAll();
        });

        http.exceptionHandling(exception -> {
            exception.accessDeniedHandler(unauthorizedHandler).authenticationEntryPoint(authEntryPointJwt);
        });

        return http.build();
    }
}

package com.bsoft.jwtauthentication.models;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class CustomUserDetails implements UserDetails{
    private final Long id;

	private final String name;

    private final String email;

	@JsonIgnore
	private final String password;

	private final Collection<? extends GrantedAuthority> authorities;

    public CustomUserDetails(Long id, String name, String email, String password, Collection<? extends GrantedAuthority> authorities) {
		this.id = id;
        this.name = name;
		this.email = email;
		this.password = password;
		this.authorities = authorities;
	}

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public Long getId() {
        return id;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    public String getEmail() {
        return email;
    }

    public String getName() {
        return name;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		CustomUserDetails user = (CustomUserDetails) o;
		return Objects.equals(email, user.email);
	}

    public static CustomUserDetails build(User user) {
		List<GrantedAuthority> authorities = user.getRoles().stream()
				.map(role -> new SimpleGrantedAuthority(role.getName().name()))
				.collect(Collectors.toList());

		return new CustomUserDetails(
				user.getId(),
                user.getName(),
				user.getEmail(), 
				user.getPassword(), 
				authorities);
	}

    @Override
    public String getUsername() {
        return this.email;
    }
}

package com.bsoft.jwtauthentication.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.bsoft.jwtauthentication.models.CustomUserDetails;
import com.bsoft.jwtauthentication.models.User;
import com.bsoft.jwtauthentication.repositories.UserRepository;

@Service
public class UserService implements UserDetailsService{
    final UserRepository userRepository;

    public UserService(@Autowired UserRepository userRepository){
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public CustomUserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
        .orElseThrow(() -> new UsernameNotFoundException("User Not Found with email: " + email));
        
        return CustomUserDetails.build(user);
    }
}

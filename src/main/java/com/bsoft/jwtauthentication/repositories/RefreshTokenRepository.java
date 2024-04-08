package com.bsoft.jwtauthentication.repositories;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

import com.bsoft.jwtauthentication.models.RefreshToken;
import com.bsoft.jwtauthentication.models.User;

public interface RefreshTokenRepository extends CrudRepository<RefreshToken, Long>{
    Optional<RefreshToken> findByToken(String token);
    
    @Modifying
    int deleteByUser(User user);
}

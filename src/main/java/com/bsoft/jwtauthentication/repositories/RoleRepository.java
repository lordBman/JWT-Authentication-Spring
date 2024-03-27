package com.bsoft.jwtauthentication.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.bsoft.jwtauthentication.models.Role;
import com.bsoft.jwtauthentication.models.Role.ERole;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(ERole name);
}


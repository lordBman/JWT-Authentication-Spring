package com.bsoft.jwtauthentication.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bsoft.jwtauthentication.configs.security.JwtUtils;
import com.bsoft.jwtauthentication.exceptions.TokenRefreshException;
import com.bsoft.jwtauthentication.models.Role.ERole;
import com.bsoft.jwtauthentication.models.CustomUserDetails;
import com.bsoft.jwtauthentication.models.RefreshToken;
import com.bsoft.jwtauthentication.models.Role;
import com.bsoft.jwtauthentication.models.User;
import com.bsoft.jwtauthentication.repositories.RoleRepository;
import com.bsoft.jwtauthentication.repositories.UserRepository;
import com.bsoft.jwtauthentication.services.RefreshTokenService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.security.Principal;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {
    public static record LoginRequest(String email, String password ) {}
    public static record SignupRequest(@NotBlank @Size(max = 50) String email, @NotBlank @Size(min = 4, max = 50) String name, @NotBlank @Size(min = 6, max = 40) String password, Set<String> roles ) {}
    public static record JwtResponse(String jwt, String refreshToken, Long id, String name, String email, List<String> roles) {}
    public static record MessageResponse(String message){};
    public static record TokenRefreshRequest(@NotBlank String refreshToken) {}
    public static record TokenRefreshResponse(String token, String refreshToken) {}

    final AuthenticationManager authenticationManager;
    final UserRepository userRepository;
    final RoleRepository roleRepository;
    final PasswordEncoder encoder;
    final JwtUtils jwtUtils;
    final RefreshTokenService refreshTokenService;

    public AuthController(
        @Autowired AuthenticationManager authenticationManager,
        @Autowired UserRepository userRepository,
        @Autowired RoleRepository roleRepository,
        @Autowired PasswordEncoder encoder,
        @Autowired JwtUtils jwtUtils,
        @Autowired RefreshTokenService refreshTokenService){

        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
    }
    
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password()));
        
        SecurityContextHolder.getContext().setAuthentication(authentication);
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        
        String jwt = jwtUtils.generateJwtToken(userDetails);
        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority()).collect(Collectors.toList());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());
        
        return ResponseEntity.ok(new JwtResponse(jwt, refreshToken.getToken(), userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles));
    }
    
    @PostMapping("/")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByEmail(signUpRequest.email())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }
        
        // Create new user's account
        User user = new User(signUpRequest.name(), signUpRequest.email(), encoder.encode(signUpRequest.password()));
        
        Set<String> strRoles = signUpRequest.roles();
        Set<Role> roles = new HashSet<>();
        
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN).orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR).orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                    }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
    
    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request, Principal principal) {
        String requestRefreshToken = request.refreshToken();
        
        return refreshTokenService.findByToken(requestRefreshToken).map(refreshTokenService::verifyExpiration).map(RefreshToken::getUser).map(user ->{
            String token = jwtUtils.generateTokenFromEamil(user.getEmail());
            return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
        }).orElseThrow(()-> new TokenRefreshException(requestRefreshToken,"Refresh token is not in database!"));
    }
    
    @GetMapping("/signout")
    public ResponseEntity<?> logoutUser(Principal principal) {
        CustomUserDetails userDetails = (CustomUserDetails)principal;
        
        Long userId = userDetails.getId();
        refreshTokenService.deleteByUserId(userId);
        
        return ResponseEntity.ok(new MessageResponse("Log out successful!"));
    }
}

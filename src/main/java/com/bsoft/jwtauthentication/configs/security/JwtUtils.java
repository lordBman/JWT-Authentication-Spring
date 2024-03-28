package com.bsoft.jwtauthentication.configs.security;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.bsoft.jwtauthentication.JwtAuthenticationApplication;
import com.bsoft.jwtauthentication.models.CustomUserDetails;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtils {
    
    @Value("${com.bsoft.spring.jwtSecret}")
    private String jwtSecret;
    
    @Value("${com.bsoft.spring.jwtExpirationMs}")
    private int jwtExpirationMs;
    
    private SecretKey key() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }
    
    public String generateJwtToken(CustomUserDetails userPrincipal) {
        return generateTokenFromEamil(userPrincipal.getEmail());
    }
    
    public String generateTokenFromEamil(String email) {
        return Jwts.builder().subject(email).issuedAt(new Date(jwtExpirationMs)).expiration(new Date((new Date()).getTime() + jwtExpirationMs)).signWith(key()).compact();
    }
    
    public String getEamilFromJwtToken(String token) {
        return Jwts.parser().verifyWith(key()).build().parseSignedClaims(token).getPayload().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().verifyWith(key()).build().parse(authToken);
            return true;
        } catch (MalformedJwtException e) {
            JwtAuthenticationApplication.logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            JwtAuthenticationApplication.logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            JwtAuthenticationApplication.logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            JwtAuthenticationApplication.logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}


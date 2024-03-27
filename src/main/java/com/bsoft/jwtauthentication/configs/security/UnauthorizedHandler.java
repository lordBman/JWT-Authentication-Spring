package com.bsoft.jwtauthentication.configs.security;

import java.io.IOException;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import com.bsoft.jwtauthentication.JwtAuthenticationApplication;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class UnauthorizedHandler implements AccessDeniedHandler{
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        JwtAuthenticationApplication.logger.error("Access denied error: {}", accessDeniedException.getMessage());
        
        //response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error: Unauthorized");
    }   
}
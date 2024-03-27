package com.bsoft.jwtauthentication.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bsoft.jwtauthentication.models.User;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @GetMapping("/")
    User signup(){
        return null;
    }
}

package com.unknownkoder.controller;


import com.unknownkoder.models.ApplicationUser;
import com.unknownkoder.models.LoginResponseDTO;
import com.unknownkoder.models.RegistrationDTO;
import com.unknownkoder.services.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/auth")
@CrossOrigin(originPatterns = "*")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;

    @RequestMapping(path = "/register")
    public ApplicationUser registerUser(@RequestBody RegistrationDTO requestBody){

        return authenticationService.registerUser(requestBody.getUsername(), requestBody.getPassword());
    }

    @RequestMapping(path = "/login")
    public LoginResponseDTO loginUser(@RequestBody RegistrationDTO requestBody){
        return authenticationService.loginResponseDTO(requestBody.getUsername(),requestBody.getPassword());
    }


}

package com.unknownkoder.controller;


import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/user")
@CrossOrigin(originPatterns = "*")
public class UserController {


    @GetMapping("/")
    public String helloUserController(){
        return "User access Level";

    }
}

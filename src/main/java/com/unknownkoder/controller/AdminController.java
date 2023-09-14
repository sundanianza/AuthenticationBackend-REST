package com.unknownkoder.controller;


import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/admin")
@CrossOrigin(originPatterns = "*")
public class AdminController {


    @GetMapping("/")
    public String helloAdimAccess(){
        return "Adim Access Level";
    }
}

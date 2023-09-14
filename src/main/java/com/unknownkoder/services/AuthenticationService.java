package com.unknownkoder.services;

import com.unknownkoder.models.ApplicationUser;
import com.unknownkoder.models.LoginResponseDTO;
import com.unknownkoder.models.Role;
import com.unknownkoder.repository.RoleRepository;
import com.unknownkoder.repository.UserRepository;
import com.unknownkoder.utils.TokenService;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@Transactional
@Slf4j
public class AuthenticationService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;


    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenService tokenService;

    public ApplicationUser registerUser(String username, String password){

       String encodedPassword = passwordEncoder.encode(password);

        Role userRole = roleRepository.findByAuthority("USER").get();

        Set<Role> authority = new HashSet<>();
        authority.add(userRole);


        return userRepository.save(new ApplicationUser(0,username,encodedPassword,authority));


    }


    public LoginResponseDTO loginResponseDTO(String username, String password){

        try{
            log.info("i am inside the loginResponseDTO");

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username,password)
            );
            String token = tokenService.generateJwt(authentication);
            return new LoginResponseDTO(userRepository.findByUsername(username).get(),token);


        }catch (AuthenticationException ex){
            return new LoginResponseDTO(null,"");


        }
    }
}

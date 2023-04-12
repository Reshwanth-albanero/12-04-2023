package com.example.demo.Controller;

import com.example.demo.Helper.JwtUtil;
import com.example.demo.Models.JwtRequest;
import com.example.demo.Models.JwtResponse;
import com.example.demo.Service.CustomUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtController {
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    CustomUser customUser;
    @Autowired
    JwtUtil jwtUtil;
    @RequestMapping(value = "/token",method = RequestMethod.POST)
    public ResponseEntity<?> generateToken(@RequestBody JwtRequest jwtRequest) throws Exception {
        System.out.println(jwtRequest);
        try{
            this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(jwtRequest.getUserName(),jwtRequest.getPassword()));
        }
        catch (UsernameNotFoundException e){
            throw new Exception("Bad Credentials");
        }
        catch (BadCredentialsException e){
            throw new Exception("Not this type bro");
        }
        UserDetails userDetails = this.customUser.loadUserByUsername(jwtRequest.getUserName());
        String token = this.jwtUtil.generateToken(userDetails);
        System.out.println("JWT"+token);
        return ResponseEntity.ok(new JwtResponse(token));

    }
}

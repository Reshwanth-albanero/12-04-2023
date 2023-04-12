package com.example.demo.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
    @GetMapping("/home")
    public String home(){
        return "this is home";
    }
//    @PreAuthorize("hasRole('ADMIN')") it is used in place of antmatched().hasRole();;;
    @GetMapping("/second-home")
    public String secondHome(){
        return "this is second home";
    }
}
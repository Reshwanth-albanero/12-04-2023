package com.example.demo.Controller;

import com.example.demo.Models.User;
import com.example.demo.Service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.net.Authenticator;
import java.util.List;

@RestController
public class UserController {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    UserService userService;
//    @RequestMapping(value = "/authenticate",method = RequestMethod.POST)
//    public ResponseEntity<User> raaaaannnnndddddooooommm(@RequestBody User user) throws Exception {
//        try{
//            authenticationManager.authenticate(
//                    new UsernamePasswordAuthenticationToken(user.getName(),user.getInnerId())
//            );
//        }
//        catch (Exception e){
//            throw new Exception("There is no user in the db of that name");
//        }
//        return new ResponseEntity<>(user ,HttpStatus.ACCEPTED);
//    }
    @PostMapping("/post")
    public ResponseEntity<User> addUser(@RequestBody User user){
        return new ResponseEntity<>(userService.addUser(user),HttpStatus.ACCEPTED);
    }
    @PutMapping("/put")
    public ResponseEntity<User> putUser(@RequestParam Integer id,@RequestParam String add){
        return new ResponseEntity<>(userService.putUser(id,add),HttpStatus.ACCEPTED);
    }
    @GetMapping("/get")
    public ResponseEntity<List<User>> getALlUsers(){
        return new ResponseEntity<>(userService.getAllUsers(), HttpStatus.ACCEPTED);
    }
    @DeleteMapping("/delete")
    public ResponseEntity<User> deleteUser(@RequestParam Integer id){
        return new ResponseEntity<>(userService.deleteUser(id),HttpStatus.ACCEPTED);
    }
}

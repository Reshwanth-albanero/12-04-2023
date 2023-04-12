package com.example.demo.Service;

import com.example.demo.Models.User;
import com.example.demo.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    UserRepository userRepository;
    public User addUser(User user) {
        userRepository.save(user);
        return user;
    }

    public User putUser(Integer id, String add) {
        User user = userRepository.findByOuterId(id);
        user.setAddress(add);
        userRepository.save(user);
        return user;
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public User deleteUser(Integer id) {
        User user = userRepository.findByOuterId(id);
        userRepository.delete(user);
        return user;
    }
}

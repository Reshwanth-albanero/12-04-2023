package com.example.demo.Models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.lang.annotation.Documented;
import java.util.Collections;
@Data
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "User")
public class User {
    @Id
    private String innerId;
    private Integer outerId;
    private String name;
    private String address;

    public User(Integer id, String name, String address) {
        this.outerId = id;
        this.name = name;
        this.address = address;
    }
}

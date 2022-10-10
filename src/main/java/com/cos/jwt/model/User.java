package com.cos.jwt.model;

import lombok.Data;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Data
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private String username;
    private String password;
    private String roles; //USER , ADMIN

    public List<String> getRoleList(){   //roles가 두개일수 있으니까 만든 것
        if(this.roles.length()>0){
            return Arrays.asList(this.roles.split(","));
        }
        return new ArrayList<>();
    }


}

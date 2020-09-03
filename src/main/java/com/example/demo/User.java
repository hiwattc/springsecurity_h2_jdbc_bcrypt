package com.example.demo;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
@Entity
public class User {
@Id
@GeneratedValue(strategy=GenerationType.AUTO)
private Long id;
private String name;

protected User() {}

public User(String name) {
this.name = name;
}

@Override
public String toString() {
return String.format("User[id=%d, name='%s']",id, name);
}
}
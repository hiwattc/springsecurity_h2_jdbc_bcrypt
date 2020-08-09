package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;


@SpringBootApplication
@RestController
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	@GetMapping("/hello")
	public String hello(){
		return "hello wolrd";
	}

	private static final Logger log = LoggerFactory.getLogger(DemoApplication.class);
    @Autowired
    UserRepository repository;
    @GetMapping("/user")
    public void user(){
     repository.save(new User("hiwatt1"));
        for(User user : repository.findAll()){
           log.info(user.toString());
        }
    }
}

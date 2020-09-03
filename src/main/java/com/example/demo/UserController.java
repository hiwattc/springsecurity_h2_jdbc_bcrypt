package com.example.demo;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class UserController {

	@RequestMapping("/admin")
	@ResponseBody
	public String getAdmin() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		return "<h1>Hello Admin " + authentication.getName() + "</h1>";
	}
	
	@RequestMapping("/user")
	@ResponseBody
	public String getUser() {
		return "<h1>Hello User</h1>";
	}
}

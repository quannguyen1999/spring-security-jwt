package com.spring.main.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PageNoSecureController {
	@GetMapping("/abc")
	public String getIndex() {
		return "index";
	}
}

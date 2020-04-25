package com.spring.main.oath;

import java.util.Optional;

import org.springframework.stereotype.Service;
@Service
public interface ApplicationUserDao {
	Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}

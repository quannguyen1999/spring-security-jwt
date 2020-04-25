package com.spring.main.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.kafka.KafkaProperties.Admin;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.AntPathMatcher;

import com.spring.main.jwt.JwtConfig;
import com.spring.main.jwt.JwtSecretKey;
import com.spring.main.jwt.JwtTokenveifier;
import com.spring.main.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import com.spring.main.oath.ApplicationUserService;

import static com.spring.main.security.ApplicationUserRole.*;

import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import static com.spring.main.security.ApplicationUserPermission.*;
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{
	private final PasswordEncoder passwordEncoder;
	private ApplicationUserService applicationUserService;
	private final SecretKey secretKey;
	private final JwtConfig jwtConfig;
	
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService,
			SecretKey secretKey, JwtConfig jwtConfig) {
		super();
		this.passwordEncoder = passwordEncoder;
		this.applicationUserService = applicationUserService;
		this.secretKey = secretKey;
		this.jwtConfig = jwtConfig;
	}
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()  //dùng để tắt chế độ () token
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(),jwtConfig,secretKey))
			.addFilterAfter(new JwtTokenveifier(secretKey, jwtConfig), JwtUsernameAndPasswordAuthenticationFilter.class)
			.authorizeRequests() //yêu cầu thẩm quyền
			.antMatchers("/","/abc").permitAll()
			.antMatchers("/api/**").hasRole(STUDENT.name())
			.anyRequest()
			.authenticated();
//			.antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//			.antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//			.antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//			.antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
//			.anyRequest()	//bất cứ request nào
//			.authenticated() //xác thực 
//			.and()
//			.httpBasic(); //form show khi reset page
//			.formLogin()
//				.loginPage("/login").permitAll()
//				.defaultSuccessUrl("/courses",true)
//				.passwordParameter("password")
//				.usernameParameter("username")
//			.and()
//			.rememberMe()
//				.tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(2))
//				.key("securedKey")
//				.rememberMeParameter("remember-me")
//			.and()
//			.logout()
//				.logoutUrl("/logout")
//				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//				.clearAuthentication(true)
//				.invalidateHttpSession(true)
//				.deleteCookies("JSESSIONID","remember-me")
//				.logoutSuccessUrl("/login");	
	}
	
	

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
	}
	
	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider=new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		return provider;
	}
	
	

//	@Bean
//	@Override
//	protected UserDetailsService userDetailsService() {
//		System.out.println("turn user fake");
//		UserDetails anna=User.builder()
//				.username("anna")
//				.password(passwordEncoder.encode("password"))
////				.roles(STUDENT.name())
//				.authorities(STUDENT.getGrantedAuthorities())
//				.build();
//		
//		UserDetails linkdaUser=User.builder()
//					.username("linda")
//					.password(passwordEncoder.encode("password"))
////					.roles(ADMIN.name())
//					.authorities(ADMIN.getGrantedAuthorities())
//					.build();
//		
//		UserDetails tomUser=User.builder()
//					.username("tom")
//					.password(passwordEncoder.encode("password"))
////					.roles(ADMINTRAINEE.name())
//					.authorities(ADMINTRAINEE.getGrantedAuthorities())
//					.build();
//		return new InMemoryUserDetailsManager(
//				anna,linkdaUser,tomUser);
//	}
	
	
}

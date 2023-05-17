package com.greatlearning.ems.employeems.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.greatlearning.ems.employeems.service.UserDetailsServiceImpl;




@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{

	 @Bean
	    public UserDetailsService userDetailsService() {
	        return new UserDetailsServiceImpl();
	    }
	     
	    @Bean
	    public BCryptPasswordEncoder passwordEncoder() {
	        return new BCryptPasswordEncoder();
	    }
	     
	    @Bean
	    public DaoAuthenticationProvider authenticationProvider() {
	        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
	        authProvider.setUserDetailsService(userDetailsService());
	        authProvider.setPasswordEncoder(passwordEncoder());
	         
	        return authProvider;
	    }
	 
	    @Override
	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	    	 auth.authenticationProvider(authenticationProvider());
	    }
	 
	    @Override
	    protected void configure(HttpSecurity http) throws Exception {
	    	 http.authorizeRequests()
			  .antMatchers("/ems/api/user","/ems/api/role").hasAnyAuthority("USER","ADMIN")
			  .antMatchers(HttpMethod.GET,"/ems/api/employees").hasAnyAuthority("USER","ADMIN")
			  .antMatchers(HttpMethod.POST,"/ems/api/employees").hasAuthority("ADMIN")
			  .antMatchers(HttpMethod.POST,"/ems/api/employees").hasAuthority("USER")
			  .antMatchers(HttpMethod.PUT,"/ems/api/employees").hasAuthority("ADMIN")
			  .antMatchers(HttpMethod.PUT,"/ems/api/employees").hasAuthority("USER")
			  .antMatchers(HttpMethod.DELETE,"/ems/api/employees").hasAuthority("ADMIN")
			  .antMatchers(HttpMethod.DELETE,"/ems/api/employees").hasAuthority("USER")
			  .anyRequest().authenticated().and().httpBasic()
			  .and().cors().and().csrf().disable();
	    }

}

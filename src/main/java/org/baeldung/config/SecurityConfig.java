package org.baeldung.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;

@Configuration
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception { // @formatter:off
    	  http.requestMatchers()
          .antMatchers("/login", "/oauth/authorize")
          .and()
          .authorizeRequests()
          .anyRequest()
          .authenticated()
          .and()
          .formLogin()
          .permitAll();
    } // @formatter:on

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception { // @formatter:off

    	/*
    	auth.inMemoryAuthentication()
            .withUser("john")
            .password(passwordEncoder().encode("123"))
            .roles("AAA","USER", "XXX");
    	
    	*/
    	
    	auth
		.ldapAuthentication()
		//.userDnPatterns("cn={0},dc=itzone,dc=pl")
		//.userDnPatterns("cn={0}")
		.userDnPatterns("cn={0},ou=users")
			.groupSearchBase("ou=groups")
			.contextSource()
			.url("ldap://192.168.1.11:30389/dc=itzone,dc=pl")
			//.url("ldap://192.168.1.11:30389")
			.managerDn("cn=admin,dc=itzone,dc=pl")
			.managerPassword("admin")
				.and()
			.passwordCompare()
				.passwordEncoder(new LdapShaPasswordEncoder())
				.passwordAttribute("userPassword");
    } // @formatter:on

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}

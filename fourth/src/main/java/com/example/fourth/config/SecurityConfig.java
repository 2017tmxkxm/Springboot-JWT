package com.example.fourth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import javax.servlet.Filter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CorsConfig corsConfig;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
       return http
               .csrf().disable()
               .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
               .and()
               .addFilter(corsConfig.corsFilter())
               .formLogin().disable()
               .httpBasic().disable()
               .authorizeHttpRequests(authroize -> authroize.antMatchers("/api/v1/user/**").hasAnyRole("ADMIN, MANAGER", "USER")
                       .antMatchers("/api/v1/manager/**").hasAnyRole("ADMIN", "MANAGER")
                       .antMatchers("/api/v1/admin/**").hasRole("ADMIN")
                       .anyRequest().permitAll())
               .build();
    }

}

package com.example.fourth.config;

import com.example.fourth.filter.MyFilter1;
import com.example.fourth.filter.MyFilter3;
import com.example.fourth.jwt.JwtAuthenticationFilter;
import com.example.fourth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import javax.servlet.Filter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private CorsConfig corsConfig;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
       return http
               //.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class)
               .csrf().disable()
               .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
               .and()
               //.addFilter(corsConfig.corsFilter())
               .formLogin().disable()
               .httpBasic().disable()
               .apply(new MyCustomDsl())
               .and()
               .authorizeHttpRequests(authroize -> authroize.antMatchers("/api/v1/user/**").hasAnyRole("ADMIN, MANAGER", "USER")
                       .antMatchers("/api/v1/manager/**").hasAnyRole("ADMIN", "MANAGER")
                       .antMatchers("/api/v1/admin/**").hasRole("ADMIN")
                       .anyRequest().permitAll())
               .build();
    }

    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http
                    .addFilter(corsConfig.corsFilter())
                    .addFilter(new JwtAuthenticationFilter(authenticationManager));
                    //.addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));
        }
    }

}

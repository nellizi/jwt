package com.cos.jwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter; //corsFilter가 bean으로 등록되어 있으니까 가능

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      http.csrf().disable();
      http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
              .and()
              .addFilter(corsFilter)  //모든 요청은 이 필터를 타게 된다, CrossOrigin 인증x,시큐리티 필터에 등록 인증o
              .formLogin().disable()   // form로그인 방식을 안 쓴다 > jwt 방식 쓰려면 이렇게 해야 됨
              .httpBasic().disable()
              .authorizeRequests()
              .antMatchers("/api/v1/user/**")
              .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
              .antMatchers("/api/v1/manager/**")
              .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
              .antMatchers("/api/v1/admin/**")
              .access("hasRole('ROLE_ADMIN')")
              .anyRequest().permitAll();

    }
}

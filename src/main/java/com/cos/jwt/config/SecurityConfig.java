package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.filtet.Myfilter3;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter; //corsFilter가 bean으로 등록되어 있으니까 가능
    private final UserRepository userRepository;


    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {           //시큐리티 필터 체인에 등록하는 방법, 이거 말고 Config로 직접 등록
     // http.addFilterBefore(new Myfilter3(), SecurityContextPersistenceFilter.class); //시큐리티가 동작하기 전에 걸러낸다.
      http.csrf().disable();                                              //STATELESS  == 세션을 사용사지 않겠다.
      http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
              .and()
              .addFilter(corsFilter)  //모든 요청은 이 필터를 타게 된다, CrossOrigin 인증x,시큐리티 필터에 등록 인증o
              .formLogin().disable()   // form로그인 방식을 안 쓴다 > jwt 방식 쓰려면 이렇게 해야 됨
              .httpBasic().disable()                   //WebSecurityConfigureAdapter가 가지고 있음
              .addFilter(new JwtAuthenticationFilter(authenticationManager()))  //AuthenticationManager 를 매개변수로 꼭 넘겨줘야 함 , 이거를 통해서 로그인을 진행하는 것
              .addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository))
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
 // .httpBasic().disable() ?
 // header에 Authorization 키값에 id,pw를 담아서 보내는 방식
 // 매 요청 시 id,pw를 담고 있기 때문에 쿠키, 세션 필요가 없다. 계속 인증하고 있기 때문에 > 암호화가 안 되는 문제
 // https 를 쓰면 id,pw가 암호화 되어서 날라간다.

 // Authorization에 토큰을 담는 방법 > 노출은 안 되어야 하지만 id,qw 원문이 아니기 때문에 그나마 좀 낫다 => Bearer 방법
 // 토큰은 유효시간도 있고 서버에서 재발급 할 수 있다.
 // bearer 방법을 쓰려면 위에서 다 비활성화 시켜 줘야 함
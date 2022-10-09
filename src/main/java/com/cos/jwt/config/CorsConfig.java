package com.cos.jwt.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter(){     // 이 아래 주석들을 필터에 걸어야 적용되는 것
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); // 내 서버가 응답을 할 때 json을 js에서 처리할 수 있게 할지 설정
        config.addAllowedHeader("*"); //모든 헤더에 응답을 허용하겠다
        config.addAllowedMethod("*"); //모든 post,get,put,delete,patch 요청을 허용하겠다.
        config.addAllowedOrigin("*"); //모든 ip에 응답을 허용하겠다
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);

    }
}

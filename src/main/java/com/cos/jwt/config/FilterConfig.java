package com.cos.jwt.config;

import com.cos.jwt.filtet.Myfilter1;
import com.cos.jwt.filtet.Myfilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration  //Ioc로 등록
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<Myfilter1> filter1(){
        FilterRegistrationBean<Myfilter1> bean = new FilterRegistrationBean<>(new Myfilter1());
        bean.addUrlPatterns("/*"); //모든 요청에서 다 해라
        bean.setOrder(0);  //필터 중에서 가장 우선순위가 높다
        return bean;
    }
    @Bean
    public FilterRegistrationBean<Myfilter2> filter2(){
        FilterRegistrationBean<Myfilter2> bean = new FilterRegistrationBean<>(new Myfilter2());
        bean.addUrlPatterns("/*"); //모든 요청에서 다 해라
        bean.setOrder(1);  //필터 중에서 가장 우선순위가 높다  > 그래도 시큐리티 필터가 제일 먼저 실행된다.
        return bean;
    }
}

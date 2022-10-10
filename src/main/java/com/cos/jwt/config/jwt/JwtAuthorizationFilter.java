package com.cos.jwt.config.jwt;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//시큐리티가 filter를 가지고 있는 필터 중 BasicAuthenticationFilter가 있다.
//권한이나 인증이 필요한 주소를 요청했을 때 위 필터를 무조건 타고 그런 주소가 아니면 타지 않는다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
        System.out.println("==need Authentication or Authorization 1==");
    }

    @Override   //인증이나 권한이 필요한 주소요청이 있을 때 이 필터를 타게 된다.
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        super.doFilterInternal(request, response, chain);
        System.out.println("need Authentication or Authorization");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader: " + jwtHeader);
    }
}

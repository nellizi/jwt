package com.cos.jwt.filtet;


import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class Myfilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        //id,pw가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답해준다.
        //요청할 때 마다 header에 Authorization 의 value 값으로 토큰을 가지고 오게 된다.
        //그 때 넘어온 토큰이 내가 만든 토큰이 맞는지 검증만 하면 된다.(RSA, HS256)

        if(req.getMethod().equals("POST")) {
            System.out.println("POST요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);
            System.out.println("필터1");

            if(headerAuth.equals("cos")){
                chain.doFilter(req,resp);
            }else{
                PrintWriter out = resp.getWriter();
                out.println("인증안됨");
            }
        }

    }
}

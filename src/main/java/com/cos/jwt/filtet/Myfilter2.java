package com.cos.jwt.filtet;


import javax.servlet.*;
import java.io.IOException;

public class Myfilter2 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        System.out.println("필터2");
        chain.doFilter(request, response);

    }
}

package com.cos.jwt.config.jwt;

import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

//스프링 시큐리티에 존재하는 필터, /login요청해서 username,pw를 post로 전송하면 저 필터가 동작을 함.
//현재는 Formlogin.disable() 상태이기 때문에 동작을 안 함 -> config에 따로 등록해줘서 동작하게끔 해야 한다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
        throws AuthenticationException{
        System.out.println("trying login");

        try {
            //System.out.println(request.getInputStream().toString()); //stream에 user정보가 들어 있다.

//            BufferedReader br=request.getReader();
//            String input=null;
//            while((input=br.readLine())!=null){
//                System.out.println(input);
//            }
            // json형싱으로 요청 시 쉽게 파싱
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(),User.class);
            System.out.println(user);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        System.out.println("==========================");

        // 로그인 정보가 일치하면 username , qw를 받아서 로그인 시도
        // 받아온 authenticationManager 로 로그인 시도를 하면 PrincipalDetailService가 실행 -> loadUserByUsername()실행 -> PrincipalDetails가 리턴
        //PrincipalDetails를 세션에 담고 -> why? 권한 관리를 위해서.
        // Jwt토큰을 만들어서 응답
       return super.attemptAuthentication(request, response);
    }
}

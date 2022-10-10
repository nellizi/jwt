package com.cos.jwt.config.jwt;

import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.hibernate.bytecode.internal.bytebuddy.PassThroughInterceptor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
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
//          System.out.println(request.getInputStream().toString()); //stream에 user정보가 들어 있다.
/*
            BufferedReader br=request.getReader();
            String input=null;
            while((input=br.readLine())!=null){
                System.out.println(input);
            }
 */
            // json형싱으로 요청 시 쉽게 파싱
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(),User.class);
            System.out.println(user);

            // 로그인 하기 위한 토큰 만들기 ->Form로그인이면 직접 만들 필요 없지만 그게 아니니까 만들어줘야 함
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 토큰으로 로그인 시도 , PrincipalDetailsService의 loadUserByUsername() 함수가 정상 실행되면 authentication이 리턴
            //DB에 있는 정보와 로그인 정보랑 일치한다.
            Authentication authentication =//매니저에 만들어준 토큰을 날리면 인증을 받는다. -> 로그인한 내 정보가 담긴다.
                    authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails=(PrincipalDetails)authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getUsername());
            System.out.println("======================================");

            //authentication 객는 세션 영역에 저장된다.(리턴 될 때) => 로그인이 되었다.
            //jwt를 사용하면서 굳이 세션에 넣는 이유? 권한 처리를 위해서
            return authentication;
        } catch (IOException e) {
           e.printStackTrace();
        }

        // 로그인 정보가 일치하면 username , qw를 받아서 로그인 시도
        // 받아온 authenticationManager 로 로그인 시도를 하면 PrincipalDetailService가 실행 -> loadUserByUsername()실행 -> PrincipalDetails가 리턴
        //PrincipalDetails를 세션에 담고 -> why? 권한 관리를 위해서.
        // Jwt토큰을 만들어서 응답
        return null;
    }

    //attemptAuthentication가 먼저 실행된 후 인증이 정상적으로 되었으면 실행된다.
    //이 때 여기서 jwt 토큰을 만들어서 request요청한 사용자에세 jwt토큰을 response 해준다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
    }
}

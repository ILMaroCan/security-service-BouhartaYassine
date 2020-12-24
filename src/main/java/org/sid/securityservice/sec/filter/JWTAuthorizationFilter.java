package org.sid.securityservice.sec.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.sid.securityservice.sec.JWTUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

public class JWTAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        if(httpServletRequest.getServletPath().equals("/refreshToken")){
            filterChain.doFilter(httpServletRequest,httpServletResponse);
        }
        else{
            String authotoken = httpServletRequest.getHeader(JWTUtil.AUTH_HEADER);
            if(authotoken==null || httpServletRequest.getServletPath().equals("/refreshToken")){
                filterChain.doFilter(httpServletRequest,httpServletResponse);
            }else{
                if (authotoken != null && authotoken.startsWith(JWTUtil.PREFIX)) {
                    try {
                        String jwt = authotoken.substring(7);
                        Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
                        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                        DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                        String username = decodedJWT.getSubject();
                        String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                        Collection<GrantedAuthority> authorities = new ArrayList<>();
                        for (String role : roles) {
                            authorities.add(new SimpleGrantedAuthority(role));
                        }
                        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                        filterChain.doFilter(httpServletRequest, httpServletResponse);
                    }
                    catch (TokenExpiredException e){
                        httpServletResponse.setHeader("Error-Message",e.getMessage());
                        httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
                    }
                }
                else{
                    filterChain.doFilter(httpServletRequest,httpServletResponse);
                }
            }
        }

    }
}

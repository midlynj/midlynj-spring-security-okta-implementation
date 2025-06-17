//package com.example.users.service;
//
//import com.example.users.constants.SecurityConstants;
//import com.example.users.helper.Authority;
//
//import com.auth0.jwt.JWT;
//import com.example.users.entity.User;
//import com.fasterxml.jackson.databind.ObjectMapper;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//
//import java.io.IOException;
//import java.util.*;
//import java.util.stream.Collectors;
//
//import static com.auth0.jwt.algorithms.Algorithm.HMAC512;
//
//public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
//     AuthenticationManager authenticationManager;
//
////    private static String jwtSecret = System.getenv("jwtSecret");
//
//
//
//    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
//        this.authenticationManager = authenticationManager;
//    }
//
//
//    @Override
//    public Authentication attemptAuthentication(HttpServletRequest request,
//                                                HttpServletResponse response)
//            throws AuthenticationException {
//
//        User user = null;
//
//        try {
//            user = new ObjectMapper().readValue(request.getInputStream(), User.class);
//
//            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(),
//                    user.getPassword(), new ArrayList<>()));
//        } catch (BadCredentialsException bce) {
//            // log auth failure event
//            throw bce;
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//    }
//
//    protected void successfulAuthentication(HttpServletRequest request,
//                                            HttpServletResponse response,
//                                            FilterChain chain,
//                                            Authentication auth)
//            throws IOException, ServletException {
//
//        User user = (User) auth.getPrincipal();
//
//        if (user.getAuthorities() == null) {
//            user.setAuthorities(Collections.singleton(new SimpleGrantedAuthority("USER")));
//
//            List<String> roles = Authority.getUserAuthorities(auth);
//
//            String token = JWT.create()
//                    .withSubject(user.getUsername())
//                    .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION))
//                    .withClaim("roles", roles)
//                    .sign(HMAC512(SecurityConstants.JWT_SECRET));
//            response.addHeader("Authorization", "Bearer " + token);
//            return;
//        }
//
//        List<String> roles = Authority.getUserAuthorities(auth);
//
//        String token = JWT.create()
//                .withSubject(user.getUsername())
//                .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION))
//                .withClaim("roles", roles)
//                .sign(HMAC512(SecurityConstants.JWT_SECRET));
//        response.addHeader("Authorization", "Bearer " + token);
//
//    }
//}

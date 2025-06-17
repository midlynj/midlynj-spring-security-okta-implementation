package com.example.books.security;

//import com.example.books.service.JwtAuthorizationFilter;
import com.example.books.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Value("${okta.oauth2.issuer}")
    private String issuer;
    @Value("${okta.oauth2.client-id}")
    private String clientId;


//    private BCryptPasswordEncoder bCryptPasswordEncoder;
//    private UserDetailsServiceImpl userDetailsService;
//    private BooksWsAuthenticationEntryPoint authenticationEntryPoint;

//    public SecurityConfig(BCryptPasswordEncoder bCryptPasswordEncoder, UserDetailsServiceImpl userDetailsService
//                          BooksWsAuthenticationEntryPoint authenticationEntryPoint
//    ) {
//        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
//        this.userDetailsService = userDetailsService;
//        this.authenticationEntryPoint = authenticationEntryPoint;
//    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authManager) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
//                                .exceptionHandling(exception -> exception.authenticationEntryPoint(authenticationEntryPoint))

                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
                        authorizationManagerRequestMatcherRegistry //.requestMatchers(HttpMethod.DELETE).hasRole("ADMIN")
//                                .requestMatchers("/book/admin").hasAnyAuthority("ADMIN")
                                .requestMatchers("/book/1").hasAnyAuthority( "OIDC_USER")
                                .requestMatchers("/book").permitAll()
                                .anyRequest().authenticated())
                .oauth2Login(Customizer.withDefaults())
                .logout(logout -> logout
                        .addLogoutHandler(logoutHandler()))
        ;
                ;
//                .and()
//                .addFilter(new JwtAuthenticationFilter(authManager))
//                .addFilter(new JwtAuthorizationFilter(authentication -> authentication, userDetailsService))
//                .httpBasic(Customizer.withDefaults())

//                .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        return http.build();
    }

    private LogoutHandler logoutHandler() {
        return (request, response, authentication) -> {
            try {
                String baseUrl = ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString();
                response.sendRedirect(issuer + "v2/logout?client_id=" + clientId + "&returnTo=" + baseUrl);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        };


//    @Bean
//    public BCryptPasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
    }
}

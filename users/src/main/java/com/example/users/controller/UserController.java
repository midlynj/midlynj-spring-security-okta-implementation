package com.example.users.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/user")
public class UserController {

    @GetMapping(path = "/login")
    public String loginUser(@AuthenticationPrincipal OAuth2User oAuth2User) {

        if (oAuth2User != null) {
            return "Username: " +oAuth2User.getName()+ "<br>" +"User authorities: " + oAuth2User.getAuthorities();
        } else {
            return null;
        }
    }

    @GetMapping("/profile")
    public String getUserProfile( @AuthenticationPrincipal OidcUser principal) {
        if (principal != null) {
            System.out.println(principal.getAuthorities());
            return "profile " + principal.getClaims();
        }
        return null;
    }


}

//package com.example.users.repository;
//
//import com.example.users.entity.User;
//import com.example.users.model.SecurityCredentials;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.stereotype.Service;
//
//import java.util.ArrayList;
//import java.util.Collections;
//import java.util.List;
//import java.util.Optional;
//
//@Service
//public class UserFakeRepository {
//    private static List<User> userList =  new ArrayList<>();
//    public UserFakeRepository(SecurityCredentials securityCredentials) {
//
//        User user = new User(securityCredentials.getUsername(), securityCredentials.getPassword(),
//                true);
//        User user1 = new User(securityCredentials.getUsername1(), securityCredentials.getPassword(),
//                true);
////        User user2 = new User(securityCredentials.getUsername2(), securityCredentials.getPassword(),
////                true);
//        user1.setAuthorities(Collections.singleton(new SimpleGrantedAuthority("ADMIN")));
////        user2.setAuthorities(Collections.singleton(new SimpleGrantedAuthority("USER")));
//
//        userList.add(user);
//        userList.add(user1);
////        userList.add(user2);
//    }
//
//    public Optional<User> getUserByUsername(String username) {
//        return userList.stream().filter(user2 -> user2.getUsername().equals(username)).findFirst();
//    }
//}

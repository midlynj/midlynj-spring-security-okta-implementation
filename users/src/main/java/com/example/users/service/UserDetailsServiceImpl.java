//package com.example.users.service;
//
//import com.example.users.entity.User;
//import com.example.users.repository.UserFakeRepository;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Service;
//
//import java.util.Optional;
//
//@Service
//public class UserDetailsServiceImpl implements UserDetailsService {
//    private static final Logger LOGGER = LoggerFactory.getLogger(UserDetailsServiceImpl.class);
//
//
//    private UserFakeRepository userFakeRepository;
//
//    public UserDetailsServiceImpl(UserFakeRepository userFakeRepository) {
//        this.userFakeRepository = userFakeRepository;
//    }
//
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//
//        Optional<User> user = userFakeRepository.getUserByUsername(username);
//
//        if (user.isPresent()) {
////            System.out.println(user.get().getAuthorities());
//            return user.get();
//        } else {
//            LOGGER.info("No user found with username" + " " + username);
//            throw new UsernameNotFoundException(username + " does not exist");
//        }
//    }
//}

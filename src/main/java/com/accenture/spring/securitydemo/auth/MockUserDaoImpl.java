package com.accenture.spring.securitydemo.auth;

import com.accenture.spring.securitydemo.security.UserRole;
import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository("mock")
public class MockUserDaoImpl implements UserDao {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public MockUserDaoImpl(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<User> selectUserByUsername(String username) {
        return getUsers().stream()
                .filter(
                    user -> username.equals(user.getUsername()))
                .findFirst();
    }

    private List<User> getUsers(){
        List<User> users = Lists.newArrayList(
                new User(UserRole.STUDENT.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "luka",
                        true,
                        true,
                        true,
                        true),
                new User(UserRole.ADMIN.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "admin",
                        true,
                        true,
                        true,
                        true),
                new User(UserRole.ADMINTRAINEE.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "trainee",
                        true,
                        true,
                        true,
                        true)
        );

        return users;
    }
}

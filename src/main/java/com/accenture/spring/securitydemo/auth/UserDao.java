package com.accenture.spring.securitydemo.auth;

import java.util.Optional;

public interface UserDao {

    Optional<User> selectUserByUsername(String username);
}

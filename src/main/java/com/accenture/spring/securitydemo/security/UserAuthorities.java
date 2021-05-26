package com.accenture.spring.securitydemo.security;

import org.springframework.security.core.GrantedAuthority;

import java.util.Set;

public enum UserAuthorities {
    STUDENT_READ("student;read"),
    STUDENT_WRITE("student;write"),
    COURSE_READ("course;read"),
    COURSE_WRITE("course;write");

    private final String authority;

    UserAuthorities(String authority){
        this.authority = authority;
    }

    public String getAuthority() {
        return authority;
    }
}

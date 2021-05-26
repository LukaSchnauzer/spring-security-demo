package com.accenture.spring.securitydemo.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

public enum UserRole {
    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(UserAuthorities.COURSE_READ,UserAuthorities.COURSE_WRITE,UserAuthorities.STUDENT_READ,UserAuthorities.STUDENT_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(UserAuthorities.COURSE_READ,UserAuthorities.STUDENT_READ));

    private final Set<UserAuthorities> authorities;

    UserRole(Set<UserAuthorities> authorities) {
        this.authorities = authorities;
    }

    public Set<UserAuthorities> getAuthorities() {
        return authorities;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities(){
        Set<SimpleGrantedAuthority> authorities = getAuthorities().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthority()))
                .collect(Collectors.toSet());

        authorities.add( new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authorities;
    }
}

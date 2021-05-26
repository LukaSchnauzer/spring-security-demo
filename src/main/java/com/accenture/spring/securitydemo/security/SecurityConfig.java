package com.accenture.spring.securitydemo.security;

import com.accenture.spring.securitydemo.auth.UserService;
import com.accenture.spring.securitydemo.jwt.JwtConfig;
import com.accenture.spring.securitydemo.jwt.JwtTokenVerifierFilter;
import com.accenture.spring.securitydemo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import javax.crypto.SecretKey;
import java.util.concurrent.TimeUnit;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    private final PasswordEncoder passwordEncoder;
    private final UserService userService;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    @Autowired
    public SecurityConfig(PasswordEncoder passwordEncoder, UserService userService, JwtConfig jwtConfig, SecretKey secretKey) {
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // <------ JWT Authentication
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(),jwtConfig,secretKey))
                .addFilterAfter(new JwtTokenVerifierFilter(jwtConfig,secretKey), JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*","/js/*").permitAll()
                .antMatchers("/api/**").hasRole(UserRole.STUDENT.name())
//                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(UserAuthorities.COURSE_WRITE.getAuthority())
//                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(UserAuthorities.COURSE_WRITE.getAuthority())
//                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(UserAuthorities.COURSE_WRITE.getAuthority())
//                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(UserRole.ADMIN.name(),UserRole.ADMINTRAINEE.name())
                .anyRequest()
                .authenticated();
        // --------------------------------------------------------------------
//                .and()
//                .httpBasic(); //<--- Basic Authentication
        // --------------------------------------------------------------------
//                .formLogin()//<---- Form based authentication
//                    .loginPage("/login")
//                    .permitAll()
//                    .passwordParameter("password") // custom parameters name
//                    .usernameParameter("username")
//                .defaultSuccessUrl("/courses",true)
//                .and()
//                .rememberMe()
//                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//                    .key("something-secret")
//                    .rememberMeParameter("remember-me") //custom parameter name
//                .and()
//                .logout()
//                    .logoutUrl("/logout") // when csrf is disabled logout should be POST not GET
//                    .clearAuthentication(true)
//                    .deleteCookies("JSESSIONID","remember-me")
//                    .logoutSuccessUrl("/login");
        // --------------------------------------------------------------------

    }

    /*
    // IN MEMORY DB
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails lukaUser = User.builder()
                .username("luka")
                .password(passwordEncoder.encode("password"))
//                .roles(UserRole.STUDENT.name()) // ROLE_STUDENT
                .authorities(UserRole.STUDENT.getGrantedAuthorities())
                .build();

        UserDetails adminUser = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("password"))
//                .roles(UserRole.ADMIN.name()) // ROLE_ADMIN
                .authorities(UserRole.ADMIN.getGrantedAuthorities())
                .build();

        UserDetails adminTraineeUser = User.builder()
                .username("trainee")
                .password(passwordEncoder.encode("password"))
//                .roles(UserRole.ADMINTRAINEE.name()) // ROLE_ADMINTREINEE
                .authorities(UserRole.ADMINTRAINEE.getGrantedAuthorities())
                .build();

        // InMemory User
        return new InMemoryUserDetailsManager(
                lukaUser,
                adminUser,
                adminTraineeUser
        );
    }*/

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    // CUSTOM USER DATA SOURCE
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(userService);
        return provider;
    }
}

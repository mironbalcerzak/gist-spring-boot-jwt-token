package com.mca.test.spring.security;

import com.mca.test.spring.application.service.UserService;
import com.mca.test.spring.security.filter.JwtAuthenticationFilter;
import com.mca.test.spring.security.filter.JwtAuthenticationFilter.JwtAuthenticationProvider;
import com.mca.test.spring.security.filter.JwtAuthenticationLoginFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.Filter;
import javax.xml.bind.DatatypeConverter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final String salt;
    private final String algorithm;

    @Autowired
    private UserService userService;

    public SecurityConfig(@Value("${security.jwt.salt}") String salt,
                          @Value("${security.jwt.algorithm}") String algorithm) {
        this.salt = salt;
        this.algorithm = algorithm;
    }

    @Bean
    public JwtAuthenticationService jwtAuthenticationService() {
        byte[] bytes = DatatypeConverter.parseBase64Binary(salt);
        return new JwtAuthenticationService(bytes, algorithm);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public UserDetailsService securityUserService() {
        return new SecurityUserService(userService);
    }

    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(jwtAuthenticationProvider());
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    protected void configure(HttpSecurity http) throws Exception {
        http
            .addFilterAfter(jwtAuthenticationGlobalFilter(), LogoutFilter.class)
            .addFilterAfter(jwtAuthenticationLoginFilter(), LogoutFilter.class)
            // in web application you should NEVER disable CSRF
            // csrf.disable()
            .csrf().requireCsrfProtectionMatcher(new AntPathRequestMatcher("/*"))
                .ignoringAntMatchers("/login").csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    private DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(securityUserService());
        return provider;
    }

    private AuthenticationProvider jwtAuthenticationProvider() {
        return new JwtAuthenticationProvider(jwtAuthenticationService(), securityUserService());
    }

    private Filter jwtAuthenticationLoginFilter() throws Exception {
        JwtAuthenticationLoginFilter filter = new JwtAuthenticationLoginFilter(jwtAuthenticationService());
        filter.setAuthenticationManager(authenticationManager());
        return filter;
    }

    private Filter jwtAuthenticationGlobalFilter() throws Exception {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManager());
        return filter;
    }

}

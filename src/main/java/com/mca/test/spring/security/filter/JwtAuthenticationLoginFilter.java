package com.mca.test.spring.security.filter;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mca.test.spring.application.ApplicationDomains.UserDetailsEntity;
import com.mca.test.spring.security.JwtAuthenticationService;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationLoginFilter extends AbstractAuthenticationProcessingFilter {

    private final JwtAuthenticationService jwtAuthenticationService;

    public JwtAuthenticationLoginFilter(JwtAuthenticationService jwtAuthenticationService) {
        super(new AntPathRequestMatcher("/login", "POST"));
        Assert.notNull(jwtAuthenticationService, "JwtAuthenticationService cannot be null");
        this.jwtAuthenticationService = jwtAuthenticationService;
        setAuthenticationSuccessHandler(successHandler());
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        try {
            LoginRequest loginRequest = new ObjectMapper().readValue(request.getInputStream(), LoginRequest.class);
            UsernamePasswordAuthenticationToken token
                    = new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());
            return getAuthenticationManager().authenticate(token);
        } catch (Exception e) {
            throw new BadCredentialsException("failed to authenticate", e);
        }
    }

    private AuthenticationSuccessHandler successHandler() {
        return (request, response, authentication) -> {
            response.setStatus(HttpServletResponse.SC_ACCEPTED);
            UserDetailsEntity principal = (UserDetailsEntity) authentication.getPrincipal();
            String[] authorities = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toArray(String[]::new);

            response.setHeader("X-Jwt-Auth",
                    jwtAuthenticationService.serialize(jwtAuthenticationService.generateToken(principal.getUsername(), authorities)));
        };
    }

    /**
     * Login Request
     */
    public static class LoginRequest {

        private final String USER_NAME_PROPERTY = "username";
        private final String USER_PASSWORD_PROPERTY = "password";

        private String username;
        private String password;

        @JsonCreator
        public LoginRequest(@JsonProperty(USER_NAME_PROPERTY) String username,
                            @JsonProperty(USER_PASSWORD_PROPERTY) String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }

    }
}

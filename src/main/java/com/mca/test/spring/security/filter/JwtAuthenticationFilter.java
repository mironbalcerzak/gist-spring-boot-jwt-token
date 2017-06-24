package com.mca.test.spring.security.filter;

import com.mca.test.spring.security.JwtAuthenticationService;
import com.mca.test.spring.security.exception.JwtValidationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ValidationException;

/**
 *
 */
public class JwtAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        String header = request.getHeader("X-Jwt-Auth");
        if (header != null) {
            return request.getHeader("X-Jwt-Auth");
        }
        return null;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return "N/A";
    }

    public static class JwtAuthenticationProvider extends PreAuthenticatedAuthenticationProvider {

        public JwtAuthenticationProvider(JwtAuthenticationService jwtAuthenticationService,
                                         UserDetailsService userDetailsService) {
            Assert.notNull(jwtAuthenticationService, "JwtAuthenticationService cannot be null");
            Assert.notNull(userDetailsService, "UserDetailsService cannot be null");
            this.setPreAuthenticatedUserDetailsService(token -> {
                try {
                    JwtAuthenticationService.JwtToken jwtToken = jwtAuthenticationService.deserialize((String) token.getPrincipal());
                    return userDetailsService.loadUserByUsername(jwtToken.getUserName());
                } catch (ValidationException e) {
                    throw new JwtValidationException(e.getMessage(), e);
                }
            });
        }

    }
}

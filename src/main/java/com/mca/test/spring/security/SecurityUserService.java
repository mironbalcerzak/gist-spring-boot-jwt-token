package com.mca.test.spring.security;

import com.mca.test.spring.application.ApplicationDomains;
import com.mca.test.spring.application.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Collection;

@Component
public class SecurityUserService implements UserDetailsService {

    private final UserService userService;

    @Autowired
    public SecurityUserService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return new SecurityUserPassword(userService.findAccountByUsername(username).getPassword(),
                userService.findDetailsByUsername(username));
    }

    public static class SecurityUserPassword extends ApplicationDomains.UserDetailsEntity implements UserDetails {

        private final String password;

        public SecurityUserPassword(String password, ApplicationDomains.UserDetailsEntity ude) {
            super(ude);
            this.password = password;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return AuthorityUtils.createAuthorityList("ROLE_USER");
        }

        @Override
        public String getPassword() {
            return password;
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }

}

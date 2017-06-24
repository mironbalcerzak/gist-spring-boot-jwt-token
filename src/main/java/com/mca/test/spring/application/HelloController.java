package com.mca.test.spring.application;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import com.mca.test.spring.application.ApplicationDomains.UserDetailsEntity;
/**
 * Hello REST controller
 */
@RestController
public class HelloController {

    @PreAuthorize("hasRole('ROLE_USER')")
    @RequestMapping(method = RequestMethod.GET, path = "/hello")
    public String example(@AuthenticationPrincipal UserDetailsEntity user) {
        return "Hello " + user.getUsername();
    }
}

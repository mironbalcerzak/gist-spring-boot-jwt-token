package com.mca.test.spring;

import com.mca.test.spring.application.service.UserService;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootApplication
@EnableAutoConfiguration
public class Bootstrap {

    public static void main(String[] args) {
        ConfigurableApplicationContext run = SpringApplication.run(Bootstrap.class, args);
        UserService userServiceBean = run.getBeanFactory().getBean(UserService.class);
        userServiceBean.addUser("user", "password", "john");
        userServiceBean.addUser("admin", "password", "ada");
    }

}

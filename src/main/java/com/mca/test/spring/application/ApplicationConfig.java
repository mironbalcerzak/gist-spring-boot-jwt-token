package com.mca.test.spring.application;

import com.mca.test.spring.application.ApplicationRepositories.UserAccountInMemoryRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static com.mca.test.spring.application.ApplicationRepositories.UserDetailsInMemoryRepository;

@Configuration
public class ApplicationConfig {

    @Bean
    public UserAccountInMemoryRepository userAccountInMemoryRepository() {
        return new UserAccountInMemoryRepository();
    }

    @Bean
    public UserDetailsInMemoryRepository userDetailsInMemoryRepository() {
        return new UserDetailsInMemoryRepository();
    }
}

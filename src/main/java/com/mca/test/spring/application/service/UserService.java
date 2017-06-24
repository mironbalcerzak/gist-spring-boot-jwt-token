package com.mca.test.spring.application.service;

import com.mca.test.spring.application.ApplicationDomains.UserAccountEntity;
import com.mca.test.spring.application.ApplicationDomains.UserDetailsEntity;
import com.mca.test.spring.application.ApplicationRepositories.UserAccountInMemoryRepository;
import com.mca.test.spring.application.ApplicationRepositories.UserDetailsInMemoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserAccountInMemoryRepository userAccountRepository;
    private final UserDetailsInMemoryRepository userDetailsRepository;

    private PasswordEncoder passwordEncoder = NoOpPasswordEncoder.getInstance();

    @Autowired
    public UserService(UserAccountInMemoryRepository userAccountRepository,
                       UserDetailsInMemoryRepository userDetailsRepository) {
        this.userAccountRepository = userAccountRepository;
        this.userDetailsRepository = userDetailsRepository;
    }

    public void addUser(String username, String password, String name) {
        UserAccountEntity uae = new UserAccountEntity();
        uae.setUsername(username);
        uae.setPassword(passwordEncoder.encode(password));
        userAccountRepository.addUserAccount(uae);

        UserDetailsEntity ude = new UserDetailsEntity();
        ude.setName(name);
        ude.setUsername(username);
        userDetailsRepository.addUserAccount(ude);
    }

    public UserDetailsEntity checkCredentials(String username, String password) {
        UserAccountEntity uae = userAccountRepository.findByUsername(username);
        if (uae == null) {
            throw new UsernameNotFoundException("username not found: " + username);
        }
        if (!uae.getPassword().equals(passwordEncoder.encode(password))) {
            throw new BadCredentialsException("bad password");
        }
        return userDetailsRepository.findByUsername(username);
    }

    public UserDetailsEntity findDetailsByUsername(String username) {
        UserDetailsEntity ude = userDetailsRepository.findByUsername(username);
        if (ude == null) {
            throw new UsernameNotFoundException(username);
        }
        return ude;
    }


    public UserAccountEntity findAccountByUsername(String username) {
        UserAccountEntity ude = userAccountRepository.findByUsername(username);
        if (ude == null) {
            throw new UsernameNotFoundException(username);
        }
        return ude;
    }

    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

}

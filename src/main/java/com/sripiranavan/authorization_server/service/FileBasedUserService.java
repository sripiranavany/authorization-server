package com.sripiranavan.authorization_server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.sripiranavan.authorization_server.entity.AppUser;
import com.sripiranavan.authorization_server.model.UserConfig;
import com.sripiranavan.authorization_server.model.UsersConfiguration;
import com.sripiranavan.authorization_server.repository.AppUserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class FileBasedUserService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(FileBasedUserService.class);

    private final PasswordEncoder passwordEncoder;
    private final AppUserRepository appUserRepository;

    public FileBasedUserService(PasswordEncoder passwordEncoder, AppUserRepository appUserRepository) {
        this.passwordEncoder = passwordEncoder;
        this.appUserRepository = appUserRepository;
    }

    @PostConstruct
    @Transactional
    public void loadUsersFromFile() {
        try {
            logger.info("Loading users from configuration file...");

            ClassPathResource resource = new ClassPathResource("users.yml");
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());

            try (InputStream inputStream = resource.getInputStream()) {
                UsersConfiguration config = mapper.readValue(inputStream, UsersConfiguration.class);
                for (UserConfig userConfig : config.getUsers()) {
                    AppUser appUser = new AppUser();
                    appUser.setUsername(userConfig.getUsername());
                    appUser.setPassword(passwordEncoder.encode(userConfig.getPassword()));
                    appUser.setRoles(userConfig.getRoles());
                    appUser.setEnabled(userConfig.isEnabled());
                    appUserRepository.save(appUser);
                    logger.info("Inserted user: {} with roles: {} into database", userConfig.getUsername(), userConfig.getRoles());
                }
                logger.info("Successfully loaded {} users into database from configuration file", config.getUsers().size());
            }
        } catch (IOException e) {
            logger.error("Failed to load users from configuration file", e);
            throw new RuntimeException("Failed to load users configuration", e);
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser = appUserRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        return User.builder()
                .username(appUser.getUsername())
                .password(appUser.getPassword())
                .roles(appUser.getRoles().toArray(new String[0]))
                .disabled(!appUser.isEnabled())
                .build();
    }

    public Map<String, UserDetails> getAllUsers() {
        return appUserRepository.findAll().stream()
                .map(appUser -> User.builder()
                        .username(appUser.getUsername())
                        .password(appUser.getPassword())
                        .roles(appUser.getRoles().toArray(new String[0]))
                        .disabled(!appUser.isEnabled())
                        .build())
                .collect(Collectors.toMap(UserDetails::getUsername, userDetails -> userDetails));
    }
}

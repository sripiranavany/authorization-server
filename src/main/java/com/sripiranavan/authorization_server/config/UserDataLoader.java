package com.sripiranavan.authorization_server.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.sripiranavan.authorization_server.entity.User;
import com.sripiranavan.authorization_server.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Data loader to populate users from YAML configuration on application startup.
 * Only loads users if the database is empty.
 */
@Component
@Order(1) // Execute early in the startup process
public class UserDataLoader implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(UserDataLoader.class);

    @Autowired
    private UserService userService;

    @Override
    public void run(String... args) throws Exception {
        logger.info("Starting user data loading process...");

        // Only load users if database is empty
        if (!userService.isDatabaseEmpty()) {
            logger.info("Users already exist in database. Skipping user data loading.");
            return;
        }

        logger.info("Database is empty. Loading users from YAML configuration...");
        loadUsersFromConfig();
    }

    private void loadUsersFromConfig() {
        try {
            logger.info("Loading users from users.yml file...");

            ClassPathResource resource = new ClassPathResource("users.yml");
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());

            try (InputStream inputStream = resource.getInputStream()) {
                UsersYamlConfig config = mapper.readValue(inputStream, UsersYamlConfig.class);

                if (config.getUsers() == null || config.getUsers().isEmpty()) {
                    logger.warn("No users found in users.yml file. Skipping user loading.");
                    return;
                }

                List<User> usersToCreate = new ArrayList<>();

                for (UserYamlConfig userConfig : config.getUsers()) {
                    try {
                        User user = createUserFromYamlConfig(userConfig);
                        usersToCreate.add(user);
                        logger.debug("Prepared user for creation: {}", userConfig.getUsername());
                    } catch (Exception e) {
                        logger.error("Failed to prepare user from config: {}", userConfig.getUsername(), e);
                    }
                }

                if (!usersToCreate.isEmpty()) {
                    List<User> createdUsers = userService.createUsers(usersToCreate);
                    logger.info("Successfully loaded {} users from users.yml into database", createdUsers.size());

                    // Log created users for verification
                    for (User user : createdUsers) {
                        logger.info("Created user: {} with roles: {}", user.getUsername(), user.getRoles());
                    }
                } else {
                    logger.warn("No valid users to create from users.yml configuration");
                }
            }
        } catch (Exception e) {
            logger.error("Failed to load users from users.yml file", e);
        }
    }

    private User createUserFromYamlConfig(UserYamlConfig userConfig) {
        String username = userConfig.getUsername();
        String password = userConfig.getPassword();
        Set<String> roles = new HashSet<>(userConfig.getRoles());
        boolean enabled = userConfig.isEnabled();

        // Validate required fields
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }
        if (password == null || password.trim().isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty for user: " + username);
        }
        if (roles == null || roles.isEmpty()) {
            throw new IllegalArgumentException("Roles cannot be null or empty for user: " + username);
        }

        User user = new User();
        user.setUsername(username.trim());
        user.setPassword(password); // Will be encoded by UserService
        user.setRoles(roles);
        user.setEnabled(enabled);
        user.setCreatedAt(Instant.now());
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);
        user.setCredentialsNonExpired(true);

        return user;
    }

    /**
     * Configuration class for users loaded from YAML.
     */
    public static class UsersYamlConfig {
        private List<UserYamlConfig> users = new ArrayList<>();

        public List<UserYamlConfig> getUsers() {
            return users;
        }

        public void setUsers(List<UserYamlConfig> users) {
            this.users = users;
        }
    }

    /**
     * Configuration class for individual user from YAML.
     */
    public static class UserYamlConfig {
        private String username;
        private String password;
        private List<String> roles = new ArrayList<>();
        private boolean enabled = true;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public List<String> getRoles() {
            return roles;
        }

        public void setRoles(List<String> roles) {
            this.roles = roles;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        @Override
        public String toString() {
            return "UserYamlConfig{" +
                    "username='" + username + '\'' +
                    ", roles=" + roles +
                    ", enabled=" + enabled +
                    '}';
        }
    }
}

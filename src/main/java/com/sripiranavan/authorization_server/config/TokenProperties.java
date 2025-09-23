package com.sripiranavan.authorization_server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;

@Component
@ConfigurationProperties(prefix = "oauth2.token")
public class TokenProperties {

    private static final Logger logger = LoggerFactory.getLogger(TokenProperties.class);

    /**
     * Authorization code expiration time in minutes
     */
    private int authCodeExpirationMinutes = 10;

    /**
     * Default access token expiration time in minutes
     */
    private int accessTokenExpirationMinutes = 30;

    /**
     * Default refresh token expiration time in days
     */
    private int refreshTokenExpirationDays = 7;

    /**
     * Client-specific token settings
     */
    private Map<String, ClientTokenSettings> clients = new HashMap<>();

    // Getters and setters
    public int getAuthCodeExpirationMinutes() {
        return authCodeExpirationMinutes;
    }

    public void setAuthCodeExpirationMinutes(int authCodeExpirationMinutes) {
        this.authCodeExpirationMinutes = authCodeExpirationMinutes;
    }

    public int getAccessTokenExpirationMinutes() {
        return accessTokenExpirationMinutes;
    }

    public void setAccessTokenExpirationMinutes(int accessTokenExpirationMinutes) {
        this.accessTokenExpirationMinutes = accessTokenExpirationMinutes;
    }

    public int getRefreshTokenExpirationDays() {
        return refreshTokenExpirationDays;
    }

    public void setRefreshTokenExpirationDays(int refreshTokenExpirationDays) {
        this.refreshTokenExpirationDays = refreshTokenExpirationDays;
    }

    public Map<String, ClientTokenSettings> getClients() {
        return clients;
    }

    public void setClients(Map<String, ClientTokenSettings> clients) {
        this.clients = clients;
    }

    @PostConstruct
    public void logConfiguration() {
        logger.info("=== TOKEN CONFIGURATION LOADED ===");
        logger.info("Auth Code Expiration: {} minutes", authCodeExpirationMinutes);
        logger.info("Default Access Token Expiration: {} minutes", accessTokenExpirationMinutes);
        logger.info("Default Refresh Token Expiration: {} days", refreshTokenExpirationDays);
        
        if (!clients.isEmpty()) {
            logger.info("Client-specific settings:");
            clients.forEach((clientId, settings) -> {
                logger.info("  {}: access={}min, refresh={}days", 
                    clientId, 
                    settings.getAccessTokenExpirationMinutes(), 
                    settings.getRefreshTokenExpirationDays());
            });
        }
        logger.info("=====================================");
    }

    /**
     * Get access token expiration minutes for a specific client
     */
    public int getAccessTokenExpirationMinutesForClient(String clientId) {
        ClientTokenSettings clientSettings = clients.get(clientId);
        if (clientSettings != null && clientSettings.getAccessTokenExpirationMinutes() > 0) {
            return clientSettings.getAccessTokenExpirationMinutes();
        }
        return accessTokenExpirationMinutes;
    }

    /**
     * Get refresh token expiration days for a specific client
     */
    public int getRefreshTokenExpirationDaysForClient(String clientId) {
        ClientTokenSettings clientSettings = clients.get(clientId);
        if (clientSettings != null && clientSettings.getRefreshTokenExpirationDays() > 0) {
            return clientSettings.getRefreshTokenExpirationDays();
        }
        return refreshTokenExpirationDays;
    }

    /**
     * Client-specific token settings
     */
    public static class ClientTokenSettings {
        private int accessTokenExpirationMinutes;
        private int refreshTokenExpirationDays;

        public int getAccessTokenExpirationMinutes() {
            return accessTokenExpirationMinutes;
        }

        public void setAccessTokenExpirationMinutes(int accessTokenExpirationMinutes) {
            this.accessTokenExpirationMinutes = accessTokenExpirationMinutes;
        }

        public int getRefreshTokenExpirationDays() {
            return refreshTokenExpirationDays;
        }

        public void setRefreshTokenExpirationDays(int refreshTokenExpirationDays) {
            this.refreshTokenExpirationDays = refreshTokenExpirationDays;
        }
    }
}

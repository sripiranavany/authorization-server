package com.sripiranavan.authorization_server.config;

import org.springframework.beans.factory.annotation.Autowired;
import com.sripiranavan.authorization_server.service.DatabaseUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import com.sripiranavan.authorization_server.config.OAuth2ClientProperties;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import javax.servlet.http.HttpServletResponse;

import java.time.Duration;
import java.util.Arrays;
import java.util.UUID;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    @Autowired
    private TokenProperties tokenProperties;
    
    @Autowired
    private ServerProperties serverProperties;
    
    @Autowired
    private OAuth2ClientProperties oauth2ClientProperties;

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationServerConfig.class);
    
    private final JWKSource<SecurityContext> jwkSource;
    
    public AuthorizationServerConfig(JWKSource<SecurityContext> jwkSource) {
        this.jwkSource = jwkSource;
    }

    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http
            .csrf().disable()
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .exceptionHandling()
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setContentType("application/json");
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"" + authException.getMessage() + "\"}");
                })
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.setContentType("application/json");
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.getWriter().write("{\"error\":\"Forbidden\",\"message\":\"" + accessDeniedException.getMessage() + "\"}");
                });
        return http.build();
    }
    
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .antMatchers("/api/**", "/oauth2/**", "/.well-known/**", "/h2-console/**", "/actuator/**").permitAll()
                .anyRequest().authenticated()
            )
            .csrf().disable()
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .headers().frameOptions().disable(); // For H2 console
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        List<RegisteredClient> clients = new ArrayList<>();
        
        // Dynamically create clients from application.yml configuration
        Map<String, OAuth2ClientProperties.ClientConfig> clientConfigs = oauth2ClientProperties.getClient();
        
        logger.info("Found {} client configurations in application.yml", clientConfigs.size());
        if (clientConfigs.isEmpty()) {
            logger.warn("No client configurations found! Falling back to hardcoded clients.");
            return createFallbackClients();
        }
        
        for (Map.Entry<String, OAuth2ClientProperties.ClientConfig> entry : clientConfigs.entrySet()) {
            String clientName = entry.getKey();
            OAuth2ClientProperties.ClientConfig clientConfig = entry.getValue();
            
            logger.info("Registering OAuth2 client: {} with grant types: {}", clientName, clientConfig.getAuthorizationGrantTypes());
            
            RegisteredClient.Builder clientBuilder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientConfig.getClientId())
                .clientSecret(passwordEncoder().encode(getClientSecret(clientName)))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            
            // Add authorization grant types from configuration
            for (String grantType : clientConfig.getAuthorizationGrantTypes()) {
                switch (grantType.toLowerCase()) {
                    case "authorization_code":
                        clientBuilder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                        break;
                    case "client_credentials":
                        clientBuilder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
                        break;
                    case "password":
                        clientBuilder.authorizationGrantType(AuthorizationGrantType.PASSWORD);
                        break;
                    case "refresh_token":
                        clientBuilder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
                        break;
                    default:
                        logger.warn("Unknown grant type: {} for client: {}", grantType, clientName);
                }
            }
            
            // Add scopes from configuration
            for (String scope : clientConfig.getScopes()) {
                clientBuilder.scope(scope);
            }
            
            // Add redirect URIs - combine from application.yml and our ServerProperties
            List<String> redirectUris = new ArrayList<>();
            if (clientConfig.getRedirectUris() != null) {
                redirectUris.addAll(clientConfig.getRedirectUris());
            }
            
            // Add additional redirect URIs from our ServerProperties for specific clients
            if ("web-client".equals(clientName)) {
                redirectUris.addAll(serverProperties.getWebClientRedirectUris());
            } else if ("mobile-client".equals(clientName)) {
                redirectUris.addAll(serverProperties.getMobileClientRedirectUris());
            }
            
            // Remove duplicates and add to client
            redirectUris.stream().distinct().forEach(clientBuilder::redirectUri);
            
            // Configure token settings
            clientBuilder.tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(tokenProperties.getAccessTokenExpirationMinutesForClient(clientName)))
                .refreshTokenTimeToLive(Duration.ofDays(tokenProperties.getRefreshTokenExpirationDaysForClient(clientName)))
                .reuseRefreshTokens(false)
                .build());
            
            // Configure client settings
            clientBuilder.clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(false)
                .requireProofKey(false)
                .build());
            
            clients.add(clientBuilder.build());
            logger.info("Successfully registered client: {} with {} redirect URIs", clientName, redirectUris.size());
        }
        
        logger.info("Registered {} OAuth2 clients dynamically from application.yml", clients.size());
        return new InMemoryRegisteredClientRepository(clients);
    }
    
    /**
     * Get client secret based on client name.
     * This maps client names to their secrets for encoding.
     */
    private String getClientSecret(String clientName) {
        switch (clientName) {
            case "api-client":
                return "api-secret";
            case "web-client":
                return "web-secret";
            case "mobile-client":
                return "mobile-secret";
            default:
                logger.warn("Unknown client: {}, using default secret", clientName);
                return "default-secret";
        }
    }
    
    /**
     * Fallback method to create hardcoded clients if configuration loading fails.
     */
    private RegisteredClientRepository createFallbackClients() {
        logger.info("Creating fallback hardcoded clients");
        
        // API Client for Client Credentials Grant
        RegisteredClient apiClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("api-client")
            .clientSecret(passwordEncoder().encode("api-secret"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .scope("read")
            .scope("write")
            .scope("admin")
            .tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(tokenProperties.getAccessTokenExpirationMinutesForClient("api-client")))
                .refreshTokenTimeToLive(Duration.ofDays(tokenProperties.getRefreshTokenExpirationDaysForClient("api-client")))
                .reuseRefreshTokens(false)
                .build())
            .clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(false)
                .requireProofKey(false)
                .build())
            .build();

        return new InMemoryRegisteredClientRepository(apiClient);
    }

    @Bean
    @Primary
    public UserDetailsService userDetailsService(DatabaseUserDetailsService databaseUserDetailsService) {
        logger.info("Configuring database-backed UserDetailsService");
        return databaseUserDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
            .issuer(serverProperties.getIssuerUrl())
            .authorizationEndpoint("/oauth2/authorize")
            .tokenEndpoint("/oauth2/token")
            .tokenIntrospectionEndpoint("/oauth2/introspect")
            .tokenRevocationEndpoint("/oauth2/revoke")
            .jwkSetEndpoint("/oauth2/jwks")
            .oidcUserInfoEndpoint("/userinfo")
            .oidcClientRegistrationEndpoint("/connect/register")
            .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(
            jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }
    
    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }
    
    @Bean
    public org.springframework.security.oauth2.jwt.JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }
    
    @Bean
    public org.springframework.security.authentication.AuthenticationManager authenticationManager(
            org.springframework.security.authentication.AuthenticationProvider authenticationProvider) {
        return new org.springframework.security.authentication.ProviderManager(Arrays.asList(authenticationProvider));
    }
    
    @Bean
    public org.springframework.security.authentication.AuthenticationProvider authenticationProvider(
            UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        org.springframework.security.authentication.dao.DaoAuthenticationProvider provider = 
            new org.springframework.security.authentication.dao.DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }
}

package com.sripiranavan.authorization_server.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/server")
@CrossOrigin(origins = "*")
public class OAuth2ServerInfoController {

    @Autowired
    private AuthorizationServerSettings authorizationServerSettings;

    @GetMapping("/info")
    public ResponseEntity<?> getServerInfo() {
        Map<String, Object> serverInfo = new HashMap<>();
        
        // Basic server information
        serverInfo.put("server_name", "Customer Care Authorization Server");
        serverInfo.put("version", "1.0.0");
        serverInfo.put("issuer", authorizationServerSettings.getIssuer());
        
        // OAuth2 endpoints
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("authorization", authorizationServerSettings.getAuthorizationEndpoint());
        endpoints.put("token", authorizationServerSettings.getTokenEndpoint());
        endpoints.put("token_introspection", authorizationServerSettings.getTokenIntrospectionEndpoint());
        endpoints.put("token_revocation", authorizationServerSettings.getTokenRevocationEndpoint());
        endpoints.put("jwks", authorizationServerSettings.getJwkSetEndpoint());
        endpoints.put("userinfo", authorizationServerSettings.getOidcUserInfoEndpoint());
        endpoints.put("client_registration", authorizationServerSettings.getOidcClientRegistrationEndpoint());
        // Note: oidcLogoutEndpoint not available in OAuth2 Authorization Server 0.4.5
        endpoints.put("logout", "/connect/logout");
        serverInfo.put("endpoints", endpoints);
        
        // Supported grant types
        List<String> grantTypes = Arrays.asList(
            "authorization_code",
            "client_credentials", 
            "refresh_token",
            "password"
        );
        serverInfo.put("grant_types_supported", grantTypes);
        
        // Supported response types
        List<String> responseTypes = Arrays.asList("code", "token");
        serverInfo.put("response_types_supported", responseTypes);
        
        // Supported scopes
        List<String> scopes = Arrays.asList(
            "openid", "profile", "email", "read", "write", "admin"
        );
        serverInfo.put("scopes_supported", scopes);
        
        // Supported client authentication methods
        List<String> clientAuthMethods = Arrays.asList(
            "client_secret_basic",
            "client_secret_post"
        );
        serverInfo.put("token_endpoint_auth_methods_supported", clientAuthMethods);
        
        // Token types
        List<String> tokenTypes = Arrays.asList("Bearer");
        serverInfo.put("token_types_supported", tokenTypes);
        
        // Additional capabilities
        Map<String, Object> capabilities = new HashMap<>();
        capabilities.put("cors_enabled", true);
        capabilities.put("pkce_supported", true);
        capabilities.put("jwt_tokens", true);
        capabilities.put("token_introspection", true);
        capabilities.put("token_revocation", true);
        capabilities.put("dynamic_client_registration", true);
        capabilities.put("user_management", true);
        serverInfo.put("capabilities", capabilities);
        
        return ResponseEntity.ok(serverInfo);
    }

    @GetMapping("/health")
    public ResponseEntity<?> getHealthStatus() {
        Map<String, Object> health = new HashMap<>();
        health.put("status", "UP");
        health.put("timestamp", System.currentTimeMillis() / 1000);
        health.put("uptime", System.currentTimeMillis() / 1000); // Simplified uptime
        
        Map<String, String> components = new HashMap<>();
        components.put("authorization_server", "UP");
        components.put("jwt_service", "UP");
        components.put("user_service", "UP");
        components.put("client_service", "UP");
        health.put("components", components);
        
        return ResponseEntity.ok(health);
    }

    @GetMapping("/endpoints")
    public ResponseEntity<?> getEndpoints() {
        Map<String, Object> apiEndpoints = new HashMap<>();
        
        // Authentication endpoints
        Map<String, String> authEndpoints = new HashMap<>();
        authEndpoints.put("login", "POST /api/auth/login");
        authEndpoints.put("logout", "POST /api/auth/logout");
        authEndpoints.put("status", "GET /api/auth/status");
        apiEndpoints.put("authentication", authEndpoints);
        
        // OAuth2 endpoints
        Map<String, String> oauth2Endpoints = new HashMap<>();
        oauth2Endpoints.put("authorize", "GET " + authorizationServerSettings.getAuthorizationEndpoint());
        oauth2Endpoints.put("token", "POST " + authorizationServerSettings.getTokenEndpoint());
        oauth2Endpoints.put("introspect", "POST " + authorizationServerSettings.getTokenIntrospectionEndpoint());
        oauth2Endpoints.put("revoke", "POST " + authorizationServerSettings.getTokenRevocationEndpoint());
        oauth2Endpoints.put("jwks", "GET " + authorizationServerSettings.getJwkSetEndpoint());
        oauth2Endpoints.put("userinfo", "GET " + authorizationServerSettings.getOidcUserInfoEndpoint());
        apiEndpoints.put("oauth2", oauth2Endpoints);
        
        // Fully API-based OAuth2 endpoints
        Map<String, String> apiOAuth2Endpoints = new HashMap<>();
        apiOAuth2Endpoints.put("api_authorize", "POST /api/oauth2/authorize");
        apiOAuth2Endpoints.put("token_exchange", "POST /api/oauth2/token-exchange");
        apiOAuth2Endpoints.put("grant_types", "GET /api/oauth2/grant-types");
        apiEndpoints.put("api_based_oauth2", apiOAuth2Endpoints);
        
        // Token management endpoints
        Map<String, String> tokenEndpoints = new HashMap<>();
        tokenEndpoints.put("introspect", "POST /api/oauth2/introspect");
        tokenEndpoints.put("revoke", "POST /api/oauth2/revoke");
        tokenEndpoints.put("validate", "GET /api/oauth2/token/validate");
        tokenEndpoints.put("info", "GET /api/oauth2/token/info");
        apiEndpoints.put("token_management", tokenEndpoints);
        
        // Client management endpoints
        Map<String, String> clientEndpoints = new HashMap<>();
        clientEndpoints.put("register", "POST /api/clients/register");
        clientEndpoints.put("get", "GET /api/clients/{clientId}");
        clientEndpoints.put("list", "GET /api/clients");
        apiEndpoints.put("client_management", clientEndpoints);
        
        // User management endpoints
        Map<String, String> userEndpoints = new HashMap<>();
        userEndpoints.put("create", "POST /api/user-management/users");
        userEndpoints.put("get", "GET /api/user-management/users/{username}");
        userEndpoints.put("list", "GET /api/user-management/users");
        userEndpoints.put("change_password", "PUT /api/user-management/users/{username}/password");
        userEndpoints.put("delete", "DELETE /api/user-management/users/{username}");
        apiEndpoints.put("user_management", userEndpoints);
        
        // Server info endpoints
        Map<String, String> serverEndpoints = new HashMap<>();
        serverEndpoints.put("info", "GET /api/server/info");
        serverEndpoints.put("health", "GET /api/server/health");
        serverEndpoints.put("endpoints", "GET /api/server/endpoints");
        apiEndpoints.put("server_info", serverEndpoints);
        
        return ResponseEntity.ok(apiEndpoints);
    }

    @GetMapping("/well-known/openid_configuration")
    public ResponseEntity<?> getOpenIdConfiguration() {
        Map<String, Object> config = new HashMap<>();
        
        String issuer = authorizationServerSettings.getIssuer();
        config.put("issuer", issuer);
        config.put("authorization_endpoint", issuer + authorizationServerSettings.getAuthorizationEndpoint());
        config.put("token_endpoint", issuer + authorizationServerSettings.getTokenEndpoint());
        config.put("userinfo_endpoint", issuer + authorizationServerSettings.getOidcUserInfoEndpoint());
        config.put("jwks_uri", issuer + authorizationServerSettings.getJwkSetEndpoint());
        config.put("registration_endpoint", issuer + authorizationServerSettings.getOidcClientRegistrationEndpoint());
        config.put("introspection_endpoint", issuer + authorizationServerSettings.getTokenIntrospectionEndpoint());
        config.put("revocation_endpoint", issuer + authorizationServerSettings.getTokenRevocationEndpoint());
        // Note: oidcLogoutEndpoint not available in OAuth2 Authorization Server 0.4.5
        config.put("end_session_endpoint", issuer + "/connect/logout");
        
        config.put("scopes_supported", Arrays.asList("openid", "profile", "email", "read", "write", "admin"));
        config.put("response_types_supported", Arrays.asList("code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"));
        config.put("grant_types_supported", Arrays.asList("authorization_code", "client_credentials", "refresh_token", "password"));
        config.put("subject_types_supported", Arrays.asList("public"));
        config.put("id_token_signing_alg_values_supported", Arrays.asList("RS256"));
        config.put("token_endpoint_auth_methods_supported", Arrays.asList("client_secret_basic", "client_secret_post"));
        config.put("code_challenge_methods_supported", Arrays.asList("S256"));
        
        return ResponseEntity.ok(config);
    }
}

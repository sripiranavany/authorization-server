package com.sripiranavan.resource_server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class ResourceServerConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Enable CORS
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            // Disable CSRF for API endpoints
            .csrf().disable()
            
            // Configure OAuth2 Resource Server
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
                .authenticationEntryPoint(authenticationEntryPoint())
                .accessDeniedHandler(accessDeniedHandler())
            )
            
            // Configure authorization rules
            .authorizeHttpRequests(authz -> authz
                // Public endpoints
                .antMatchers("/health", "/actuator/**").permitAll()
                .antMatchers("/public/**").permitAll()
                
                // Protected endpoints requiring authentication
                .antMatchers("/protected/**").authenticated()
                
                // Admin endpoints requiring admin scope
                .antMatchers("/admin/**").hasAuthority("SCOPE_admin")
                
                // User endpoints requiring read scope
                .antMatchers("/users/**").hasAnyAuthority("SCOPE_read", "SCOPE_write")
                
                // Default: require authentication for all other endpoints
                .anyRequest().authenticated()
            );

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        
        // Convert JWT scopes to Spring Security authorities
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            // Handle scope as both string and array
            Object scopeClaim = jwt.getClaim("scope");
            if (scopeClaim == null) {
                return Collections.emptyList();
            }
            
            java.util.List<String> scopes = new java.util.ArrayList<>();
            
            if (scopeClaim instanceof String) {
                // Handle scope as space-separated string
                String scopeString = (String) scopeClaim;
                if (!scopeString.isEmpty()) {
                    scopes.addAll(Arrays.asList(scopeString.split(" ")));
                }
            } else if (scopeClaim instanceof java.util.List) {
                // Handle scope as array/list
                @SuppressWarnings("unchecked")
                java.util.List<String> scopeList = (java.util.List<String>) scopeClaim;
                scopes.addAll(scopeList);
            }
            
            return scopes.stream()
                    .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                    .collect(Collectors.toList());
        });
        
        return converter;
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
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) -> {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            
            String errorResponse = String.format(
                "{\"error\":\"unauthorized\",\"error_description\":\"%s\",\"message\":\"Invalid or missing access token\",\"timestamp\":\"%s\",\"path\":\"%s\",\"status\":401}",
                authException.getMessage().replace("\"", "\\\""),
                Instant.now().toString(),
                request.getRequestURI()
            );
            
            response.getWriter().write(errorResponse);
            response.getWriter().flush();
        };
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (HttpServletRequest request, HttpServletResponse response, org.springframework.security.access.AccessDeniedException accessDeniedException) -> {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            
            String errorResponse = String.format(
                "{\"error\":\"access_denied\",\"error_description\":\"%s\",\"message\":\"Insufficient privileges to access this resource\",\"timestamp\":\"%s\",\"path\":\"%s\",\"status\":403}",
                accessDeniedException.getMessage().replace("\"", "\\\""),
                Instant.now().toString(),
                request.getRequestURI()
            );
            
            response.getWriter().write(errorResponse);
            response.getWriter().flush();
        };
    }
}

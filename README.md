# OAuth2 Authorization Server - Fully API-Based Implementation

A comprehensive OAuth2 Authorization Server built with Spring Boot that provides a complete API-based authentication and authorization solution.

## Features

- **Multiple OAuth2 Grant Types**: Authorization Code, Client Credentials, Resource Owner Password Credentials, Refresh Token
- **JWT Token Support**: RSA-signed JWT tokens with proper key management
- **API-First Design**: All operations available through REST APIs
- **Client Management**: Dynamic client registration and management
- **User Management**: Complete user lifecycle management APIs
- **Token Management**: Token introspection, validation, and revocation
- **CORS Support**: Cross-origin resource sharing enabled for web applications
- **Comprehensive Logging**: Detailed security and OAuth2 logging
- **Health Monitoring**: Built-in health check and server information endpoints

## Quick Start

### Prerequisites
- Java 8 or higher
- Maven 3.6+

### Running the Server
```bash
mvn spring-boot:run
```

The server will start on `http://localhost:9000`

## API Documentation

### Server Information
- **GET** `/api/server/info` - Get server information and capabilities
- **GET** `/api/server/health` - Health check endpoint
- **GET** `/api/server/endpoints` - List all available API endpoints
- **GET** `/api/server/well-known/openid_configuration` - OpenID Connect configuration

### Authentication APIs
- **POST** `/api/auth/login` - User login
- **POST** `/api/auth/logout` - User logout  
- **GET** `/api/auth/status` - Get authentication status

### OAuth2 Standard Endpoints
- **GET** `/oauth2/authorize` - Authorization endpoint (browser-based)
- **POST** `/oauth2/token` - Token endpoint
- **POST** `/oauth2/introspect` - Token introspection
- **POST** `/oauth2/revoke` - Token revocation
- **GET** `/oauth2/jwks` - JSON Web Key Set
- **GET** `/userinfo` - User information endpoint

### Fully API-Based OAuth2 Endpoints
- **POST** `/api/oauth2/authorize` - API-based authorization (no browser needed)
- **POST** `/api/oauth2/token-exchange` - Enhanced token exchange
- **GET** `/api/oauth2/grant-types` - Available grant types and usage

### Token Management APIs
- **POST** `/api/oauth2/introspect` - Introspect token details
- **POST** `/api/oauth2/revoke` - Revoke access token
- **GET** `/api/oauth2/token/validate` - Validate token
- **GET** `/api/oauth2/token/info` - Get token information

### Client Management APIs
- **POST** `/api/clients/register` - Register new OAuth2 client
- **GET** `/api/clients/{clientId}` - Get client details
- **GET** `/api/clients` - List all clients

### User Management APIs
- **POST** `/api/user-management/users` - Create new user
- **GET** `/api/user-management/users/{username}` - Get user details
- **GET** `/api/user-management/users` - List all users
- **PUT** `/api/user-management/users/{username}/password` - Change user password
- **DELETE** `/api/user-management/users/{username}` - Delete user

## Usage Examples

### 🔥 Fully API-Based OAuth2 Flows (No Browser Required)

#### 1. Client Credentials Grant (API-to-API)

```bash
# Get access token - Fully API-based
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "api-client:api-secret" \
  -d "grant_type=client_credentials&scope=read write"
```

#### 2. Resource Owner Password Credentials Grant (Mobile Apps)

```bash
# Get access token with user credentials - Fully API-based (includes refresh_token)
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "mobile-client:mobile-secret" \
  -d "grant_type=password&username=user&password=password&scope=read write"
```

#### 3. API-Based Authorization Code Grant (No Browser Redirects)

```bash
# Step 1: Get authorization code via API (no browser needed)
curl -X POST http://localhost:9000/api/oauth2/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "web-client",
    "redirectUri": "http://localhost:3000/callback",
    "username": "user",
    "password": "password",
    "scope": "openid profile read write",
    "state": "xyz123"
  }'

# Response will include authorization_code
# {
#   "authorization_code": "auth_code_abc123...",
#   "state": "xyz123",
#   "redirect_uri": "http://localhost:3000/callback",
#   "expires_in": 600
# }

# Step 2: Exchange code for tokens (includes refresh_token)
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "web-client:web-secret" \
  -d "grant_type=authorization_code&code=auth_code_abc123...&redirect_uri=http://localhost:3000/callback"
```

#### 4. Refresh Token Usage

```bash
# Use refresh token to get new access token
curl -X POST http://localhost:9000/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "web-client:web-secret" \
  -d "grant_type=refresh_token&refresh_token=YOUR_REFRESH_TOKEN"
```

### 📋 Get Available Grant Types

```bash
# See all available grant types and their API usage
curl -X GET http://localhost:9000/api/oauth2/grant-types
```

### 4. Token Introspection

```bash
# Introspect token
curl -X POST http://localhost:9000/api/oauth2/introspect \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_ACCESS_TOKEN"}'
```

### 5. Client Registration

```bash
# Register new client
curl -X POST http://localhost:9000/api/clients/register \
  -H "Content-Type: application/json" \
  -d '{
    "clientName": "My Application",
    "grantTypes": ["authorization_code", "refresh_token"],
    "redirectUris": ["http://localhost:8080/callback"],
    "scopes": ["read", "write"]
  }'
```

### 6. User Management

```bash
# Create new user
curl -X POST http://localhost:9000/api/user-management/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "password": "password123",
    "roles": ["USER", "ADMIN"]
  }'
```

## Pre-configured Clients

The server comes with three pre-configured OAuth2 clients:

### API Client (Client Credentials)
- **Client ID**: `api-client`
- **Client Secret**: `api-secret`
- **Grant Types**: `client_credentials`, `refresh_token`
- **Scopes**: `read`, `write`, `admin`

### Web Client (Authorization Code)
- **Client ID**: `web-client`
- **Client Secret**: `web-secret`
- **Grant Types**: `authorization_code`, `refresh_token`
- **Redirect URIs**: `http://localhost:3000/callback`, `http://localhost:8080/login/oauth2/code/custom`
- **Scopes**: `openid`, `profile`, `email`, `read`, `write`

### Mobile Client (Password Grant)
- **Client ID**: `mobile-client`
- **Client Secret**: `mobile-secret`
- **Grant Types**: `password`, `refresh_token`
- **Scopes**: `read`, `write`, `openid`, `profile`

## Default User

- **Username**: `user`
- **Password**: `password`
- **Roles**: `USER`

## Configuration

The server can be configured through `application.yml`:

```yaml
server:
  port: 9000

spring:
  security:
    oauth2:
      authorization-server:
        jwt:
          key-value: secret
```

## Security Features

- **JWT Tokens**: RSA-signed JWT tokens with configurable expiration
- **CORS Support**: Configurable cross-origin resource sharing
- **Token Validation**: Comprehensive token validation and introspection
- **Secure Defaults**: Secure configuration out of the box
- **Audit Logging**: Detailed security event logging

## Development

### Building
```bash
mvn clean compile
```

### Testing
```bash
mvn test
```

### Running with Custom Profile
```bash
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

## Monitoring

- **Health Check**: `GET /api/server/health`
- **Actuator Endpoints**: `/actuator/health`, `/actuator/info`, `/actuator/metrics`
- **H2 Console**: `http://localhost:9000/h2-console` (development only)

## API Response Format

All API responses follow a consistent JSON format:

### Success Response
```json
{
  "data": { ... },
  "status": "success",
  "timestamp": 1640995200
}
```

### Error Response
```json
{
  "error": "error_code",
  "error_description": "Human readable error description",
  "timestamp": 1640995200
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License.

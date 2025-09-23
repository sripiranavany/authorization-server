# OAuth2 Authorization Server

A production-ready OAuth2 Authorization Server built with Spring Boot 2.7.18, featuring comprehensive API-based authentication, JWT tokens, and enterprise-grade logging with Log4j2.

## 🚀 Features

- **Complete OAuth2 Implementation**: Authorization Code, Client Credentials, Refresh Token grants
- **JWT Token Support**: RSA-signed JWT tokens with configurable expiration
- **API-First Design**: All operations available through REST APIs (no browser redirects required)
- **Database-Backed Storage**: H2 database for authorization codes, refresh tokens, and users
- **Enterprise Logging**: Log4j2 with SLF4J facade, comprehensive audit logging
- **Production Security**: BCrypt password encoding, secure token management
- **CORS Support**: Cross-origin resource sharing for web applications
- **Health Monitoring**: Built-in health checks and server information endpoints

## 🛠️ Technology Stack

- **Framework**: Spring Boot 2.7.18
- **Security**: Spring Security OAuth2 Authorization Server
- **Database**: H2 (in-memory for development)
- **Logging**: Log4j2 2.20.0 + SLF4J 1.7.36
- **Token Format**: JWT with RSA signing
- **Build Tool**: Maven
- **Java Version**: 21 (compatible with Java 8+)

## ⚡ Quick Start

### Prerequisites
- Java 8 or higher
- Maven 3.6+

### Running the Server
```bash
# Clone and navigate to project
git clone <repository-url>
cd authorization-server

# Run the server
./mvnw spring-boot:run
```

The server will start on `http://localhost:9000`

### Verify Installation
```bash
# Check server health
curl http://localhost:9000/api/server/health

# Get server information
curl http://localhost:9000/api/server/info
```

## 📚 API Documentation

### 🔐 OAuth2 Endpoints

#### Authorization (API-Based)
```bash
POST /api/oauth2/authorize
```
Get authorization code without browser redirects.

#### Token Exchange
```bash
POST /api/oauth2/token
```
Exchange authorization codes for JWT access tokens.

#### Refresh Token
```bash
POST /api/oauth2/refresh
```
Refresh expired access tokens.

#### Token Introspection
```bash
POST /api/oauth2/introspect
POST /api/oauth2/introspect/refresh
```
Validate and inspect token details.

### 🔧 Token Management

#### Token Validation
```bash
GET /api/oauth2/token/validate?token=<jwt_token>
```

#### Token Information
```bash
GET /api/oauth2/token/info?token=<jwt_token>
```

#### Token Revocation
```bash
POST /api/oauth2/revoke
```

### 📊 Server Information

#### Server Health
```bash
GET /api/server/health
```

#### Server Configuration
```bash
GET /api/server/info
GET /api/server/endpoints
GET /api/server/token-config
```

#### Grant Types Information
```bash
GET /api/oauth2/grant-types
```

#### Token Statistics
```bash
GET /api/oauth2/statistics
```

## 🎯 Usage Examples

### 1. API-Based Authorization Code Flow

```bash
# Step 1: Get authorization code (no browser needed)
curl -X POST http://localhost:9000/api/oauth2/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "web-client",
    "username": "admin",
    "password": "admin123",
    "scope": "read write",
    "redirect_uri": "http://localhost:3000/callback"
  }'

# Response:
# {
#   "authorization_code": "auth_code_5563c10646bc4fdea02714946676ade2",
#   "scope": "read write",
#   "redirect_uri": "http://localhost:3000/callback",
#   "message": "Authorization successful - use this code to get access token",
#   "expires_in": 60
# }

# Step 2: Exchange code for JWT tokens
curl -X POST http://localhost:9000/api/oauth2/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "client_id": "web-client",
    "client_secret": "web-secret",
    "code": "auth_code_5563c10646bc4fdea02714946676ade2",
    "redirect_uri": "http://localhost:3000/callback"
  }'
```

### 2. Refresh Token Flow

```bash
curl -X POST http://localhost:9000/api/oauth2/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "refresh_token",
    "client_id": "web-client",
    "refresh_token": "refresh_token_3d0a15d23e9649dab715ca287c97218b"
  }'
```

### 3. Token Introspection

```bash
curl -X POST http://localhost:9000/api/oauth2/introspect \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJraWQiOiJmZjE3ZTk0ZC03NzQyLTQ2YWEtYjAyYS01N2QwMTNmNDRhYzIi..."
  }'
```

## ⚙️ Configuration

### Pre-configured OAuth2 Clients

#### Web Client (Authorization Code)
- **Client ID**: `web-client`
- **Client Secret**: `web-secret`
- **Grant Types**: `authorization_code`, `refresh_token`
- **Scopes**: `openid`, `profile`, `email`, `read`, `write`
- **Redirect URIs**: `http://localhost:3000/callback`

#### API Client (Client Credentials)
- **Client ID**: `api-client`
- **Client Secret**: `api-secret`
- **Grant Types**: `client_credentials`, `refresh_token`
- **Scopes**: `read`, `write`, `admin`

#### Mobile Client (Password Grant)
- **Client ID**: `mobile-client`
- **Client Secret**: `mobile-secret`
- **Grant Types**: `password`, `refresh_token`
- **Scopes**: `read`, `write`, `openid`, `profile`

### Default Users

The server comes with pre-configured users loaded from `users.yml`:

- **admin** / **admin123** (Roles: ADMIN, USER)
- **api-user** / **api123** (Roles: USER)
- **service-account** / **service123** (Roles: SERVICE)
- **robi-operator** / **robi123** (Roles: OPERATOR, USER)

### Token Configuration

```yaml
oauth2:
  token:
    # Authorization code expiration (minutes)
    auth-code-expiration-minutes: 1
    
    # Default token expiration
    access-token-expiration-minutes: 30
    refresh-token-expiration-days: 7
    
    # Client-specific settings
    clients:
      web-client:
        access-token-expiration-minutes: 5
        refresh-token-expiration-days: 1
```

## 📝 Logging

### Log4j2 Configuration

The server uses Log4j2 with SLF4J facade for enterprise-grade logging:

- **Debug Log**: `/hms/logs/authorization-server/authorization-server-debug.log`
  - 30-minute rotation, 100MB max size
  - Application debug information

- **Audit Log**: `/hms/logs/authorization-server/authorization-server-audit.log`
  - 10-minute rotation, 50MB max size
  - OAuth2 request/response audit trail

### Audit Logging Features

- **Request/Response Logging**: Complete HTTP audit trail
- **OAuth2 Operation Logging**: All OAuth2 flows with client details
- **Sensitive Data Masking**: Automatic masking of tokens and credentials
- **Structured Logging**: JSON-formatted logs for easy parsing

## 🔒 Security Features

- **JWT Tokens**: RSA-signed JWT tokens with proper validation
- **BCrypt Password Encoding**: Secure password storage
- **Token Expiration**: Configurable token lifetimes
- **Refresh Token Rotation**: Enhanced security with token rotation
- **CORS Support**: Configurable cross-origin resource sharing
- **Audit Trail**: Comprehensive security event logging
- **Database Token Storage**: Secure token persistence and cleanup

## 🏗️ Architecture

### Database Schema

- **Users**: User accounts with roles and metadata
- **Authorization Codes**: Temporary codes for OAuth2 flows
- **Refresh Tokens**: Long-lived tokens for token refresh

### Token Management

- **Automatic Cleanup**: Scheduled cleanup of expired tokens
- **Token Statistics**: Real-time token usage metrics
- **Token Introspection**: Detailed token validation and information

## 🚀 Development

### Building
```bash
./mvnw clean compile
```

### Testing
```bash
./mvnw test
```

### Running with Profiles
```bash
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

### Accessing H2 Console
- URL: `http://localhost:9000/h2-console`
- JDBC URL: `jdbc:h2:mem:authdb`
- Username: `sa`
- Password: `password`

## 📊 Monitoring

### Health Checks
```bash
# Application health
GET /api/server/health

# Spring Actuator endpoints
GET /actuator/health
GET /actuator/info
GET /actuator/metrics
```

### Token Statistics
```bash
# Get token usage statistics
GET /api/oauth2/statistics
```

## 🔧 Production Deployment

### Environment Variables

```bash
# Server configuration
SERVER_PORT=9000

# Database configuration (for production)
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/oauth2db
SPRING_DATASOURCE_USERNAME=oauth2user
SPRING_DATASOURCE_PASSWORD=secure_password

# JWT signing key (use strong key in production)
SPRING_SECURITY_OAUTH2_AUTHORIZATION_SERVER_JWT_KEY_VALUE=your-production-key
```

### Security Recommendations

1. **Use PostgreSQL/MySQL** instead of H2 for production
2. **Configure strong JWT signing keys**
3. **Enable HTTPS** for all communications
4. **Set up proper CORS policies**
5. **Monitor audit logs** for security events
6. **Implement rate limiting** for API endpoints

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

For support and questions:
- Create an issue in the repository
- Check the API documentation above
- Review the audit logs for troubleshooting

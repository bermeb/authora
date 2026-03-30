# Authora 🛡️

**Authora** is a production-ready, reusable authentication and authorization service built with Java 21 and Spring Boot 4. It provides a robust foundation for modern web applications, handling everything from JWT management to OAuth2 integration and security auditing.

## 🚀 Features

- **JWT Authentication**: Secure stateless authentication using Access and Refresh tokens with support for token rotation and revocation.
- **OAuth2 Integration**: Ready-to-use social login capabilities (Google, GitHub, etc.) via Spring Security.
- **Advanced Security**:
    - **Peppered Hashing**: Passwords are hashed using BCrypt with a configurable server-side pepper for maximum protection.
    - **Password Policies**: Enforceable complexity requirements (length, casing, digits, special characters).
    - **Rate Limiting**: Built-in protection against brute-force attacks using Bucket4j.
- **Account Management**:
    - Email verification workflows.
    - Secure password reset via time-limited tokens.
    - Automated email notifications using Thymeleaf templates.
- **Audit Logging**: Comprehensive tracking of security-sensitive events (logins, failed attempts, password changes).
- **Admin Tools**: Dedicated endpoints for user management and system monitoring.
- **API Documentation**: Fully documented REST API using OpenAPI 3.1.

## 🛠️ Tech Stack

- **Language**: Java 21
- **Framework**: Spring Boot 4.0.4
- **Security**: Spring Security, JJWT (io.jsonwebtoken)
- **Database**: PostgreSQL (with H2 support for local development)
- **Migrations**: Flyway
- **Caching**: Caffeine Cache
- **Utilities**: Lombok, Gson, Bucket4j
- **Documentation**: OpenAPI 3.1

## 📂 Project Structure

```text
src/main/java/dev/bermeb/authora/
├── config/             # Spring & Application configuration
├── controller/         # REST API endpoints
├── exception/          # Error handling & Problem Details
├── filter/             # Security & Rate limiting filters
├── model/              # JPA Entities & Enums
├── repository/         # Database access layers
├── security/           # OAuth2 & JWT security logic
├── service/            # Business logic & integrations
└── util/               # Cryptography & validation helpers
```

## 📋 Prerequisites

- JDK 21
- Maven 3.9+
- PostgreSQL (optional, defaults to H2 in-memory)

## ⚙️ Configuration

The application is highly configurable via `src/main/resources/application.yml` or environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | Secret key for signing JWTs | *Change in Prod!* |
| `JWT_EXPIRY_MINUTES` | Access token lifespan | `15` |
| `PW_PEPPER` | Server-side password pepper | *Change in Prod!* |
| `RATE_LIMIT_ENABLED` | Enable brute-force protection | `true` |
| `FEATURE_EMAIL_VERIFY`| Require email verification | `true` |
| `DB_URL` | Database connection URL | `jdbc:h2:mem...` |
| `DB_USER` | Database username | `sa` |
| `DB_PASSWORD` | Database password | *(empty)* |
| `SMTP_HOST` | Email server host | `localhost` |
| `SMTP_PORT` | Email server port | `1025` |

### 🔑 OAuth2 Setup

To enable social login, add your provider credentials to `application.yml` or set them as environment variables:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope: profile,email
```

## 🚀 Getting Started

1. **Clone the repository**:
   ```bash
   git clone https://github.com/bermeb/authora.git
   cd authora
   ```

2. **Build the project**:
   ```bash
   ./mvnw clean install
   ```

3. **Run the application**:
   ```bash
   ./mvnw spring-boot:run
   ```

The API will be available at `http://localhost:8080`.
The API specification is available in `src/main/resources/openapi.yaml`.

## 🖥️ Frontend Demo

A live demo is available at **[authora.bermeb.dev](https://authora.bermeb.dev)**.

The demo frontend source code is available in the **[authora-demo](https://github.com/bermeb/authora-demo)** repository — built with React + Vite, 
it demonstrates user registration, login, OAuth2 flows, protected routes and refresh token rotation.

## 🧪 Testing

The project includes a comprehensive test suite covering controllers, services, and security logic:

```bash
./mvnw test
```

## ⚖️ License

This project is licensed under the **PolyForm Noncommercial License 1.0.0**. 

- **Personal/Educational Use**: Permitted.
- **Commercial Use**: Prohibited without explicit written permission from the author.

See the [LICENSE](LICENSE) file for the full license text.

## ✉️ Contact

Developed by **Bernhard Mebert**. For inquiries or permission requests, please reach out via the repository's contact channels.

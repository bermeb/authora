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
- **API Documentation**: Fully documented REST API using OpenAPI 3.0 (Swagger).

## 🛠️ Tech Stack

- **Language**: Java 21
- **Framework**: Spring Boot 4.0.4
- **Security**: Spring Security, JJWT (io.jsonwebtoken)
- **Database**: PostgreSQL (with H2 support for local development)
- **Migrations**: Flyway
- **Caching**: Caffeine Cache
- **Utilities**: Lombok, Gson, Bucket4j
- **Documentation**: OpenAPI / Swagger UI

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
| `DB_URL` | PostgreSQL connection URL | `jdbc:h2:mem...` |

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
The Swagger UI documentation can be accessed at `http://localhost:8080/swagger-ui.html`.

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

Developed by **bermeb**. For inquiries or permission requests, please reach out via the repository's contact channels.

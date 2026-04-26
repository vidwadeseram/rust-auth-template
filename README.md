# rust-auth-template

Production-ready authentication API template built with **Axum**, **SQLx**, and **PostgreSQL**. Ships with Docker Compose, automated curl tests, and GitHub Actions CI.

A high-performance Rust starting point for any backend that needs user authentication, RBAC, and email flows.

## Features

- **Core Auth** — Register, login, logout, token refresh with JWT (HS256)
- **Email Verification** — Verify-email flow with expiring tokens via SMTP
- **Password Reset** — Forgot-password / reset-password with one-time tokens
- **RBAC** — Role-based access control with permissions, user management, and admin endpoints
- **Docker** — Single `docker compose up` to spin up app + PostgreSQL
- **CI** — GitHub Actions workflow that builds Docker, runs curl tests, and reports status
- **Error Handling** — Structured `AppError` enum with proper HTTP status mapping

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Framework | Axum |
| Database | SQLx (PostgreSQL) |
| Auth | jsonwebtoken (HS256) + argon2 |
| Validation | validator |
| Serialization | serde + serde_json |
| Email | lettre (MailHog for dev) |
| Logging | tracing + tracing-subscriber |
| Errors | thiserror |
| Container | Docker Compose |

## Quick Start

```bash
# Clone
git clone https://github.com/vidwadeseram/rust-auth-template.git
cd rust-auth-template

# Configure
cp .env.example .env
# Edit .env — set JWT_SECRET for production

# Launch
docker compose up --build

# API available at http://localhost:8003
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgres://postgres:postgres@db:5432/authdb` | PostgreSQL connection string |
| `JWT_SECRET` | `change-me-in-production` | HMAC secret for JWT signing |
| `JWT_ACCESS_EXPIRE_MINUTES` | `15` | Access token lifetime |
| `JWT_REFRESH_EXPIRE_DAYS` | `7` | Refresh token lifetime |
| `SMTP_HOST` | `mailhog` | SMTP server hostname |
| `SMTP_PORT` | `1025` | SMTP server port |
| `APP_PORT` | `8003` | Application port |

## API Endpoints

### Authentication

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/api/v1/auth/register` | Register a new user | No |
| `POST` | `/api/v1/auth/login` | Login with email + password | No |
| `POST` | `/api/v1/auth/refresh` | Refresh access token | No (send refresh token) |
| `POST` | `/api/v1/auth/logout` | Logout (invalidates refresh token) | Yes |
| `GET` | `/api/v1/auth/me` | Get current user profile | Yes |
| `POST` | `/api/v1/auth/verify-email` | Verify email with token | No |
| `POST` | `/api/v1/auth/forgot-password` | Request password reset email | No |
| `POST` | `/api/v1/auth/reset-password` | Reset password with token | No |

### Admin & RBAC

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `GET` | `/api/v1/admin/roles` | List all roles | `super_admin` |
| `GET` | `/api/v1/admin/users` | List all users with roles | `super_admin` |
| `POST` | `/api/v1/admin/users/{id}/roles` | Assign role to user | `super_admin` |
| `DELETE` | `/api/v1/admin/users/{id}/roles` | Remove role from user | `super_admin` |
| `POST` | `/api/v1/admin/roles/{id}/permissions` | Assign permission to role | `super_admin` |

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |

## Project Structure

```
rust-auth-template/
├── src/
│   ├── main.rs              # Axum app + server startup
│   ├── config.rs            # Environment config
│   ├── models.rs            # SQLx models (User, Role, Permission…)
│   ├── handlers/
│   │   ├── auth.rs          # Auth endpoints
│   │   └── admin.rs         # Admin/RBAC endpoints
│   ├── routes.rs            # Route registration
│   ├── auth.rs              # JWT middleware + password hashing
│   ├── errors.rs            # AppError enum
│   └── email.rs             # SMTP email sender
├── migrations/              # SQLx migrations
├── tests/
│   └── test_api.sh          # Curl-based integration tests
├── docker/
│   └── Dockerfile
├── docker-compose.yml
├── .github/workflows/ci.yml
├── .env.example
├── Cargo.toml
└── README.md
```

## Testing

```bash
# Run curl test suite against running instance
bash tests/test_api.sh http://localhost:8003/api/v1
```

The test script covers:
- User registration and login
- Token refresh and logout
- Email verification flow
- Password reset flow
- RBAC (403 without role, 200 with `super_admin`)
- Admin user/role management

## Response Format

All responses follow a consistent structure:

```json
// Success
{
  "data": {
    "user": { "id": "...", "email": "..." },
    "access_token": "...",
    "refresh_token": "..."
  }
}

// Error
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Invalid or expired token."
  }
}
```

## License

MIT

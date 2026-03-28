--
-- V1__initial_schema.sql  —  Initial Database Schema
--
CREATE TABLE users
(
    id                    UUID PRIMARY KEY      DEFAULT gen_random_uuid(),
    email                 VARCHAR(255) NOT NULL UNIQUE,
    password_hash         VARCHAR(255),

    first_name            VARCHAR(100) NOT NULL,
    last_name             VARCHAR(100) NOT NULL,
    email_verified        BOOLEAN      NOT NULL DEFAULT FALSE,
    enabled               BOOLEAN      NOT NULL DEFAULT TRUE,
    account_locked        BOOLEAN      NOT NULL DEFAULT FALSE,
    locked_until          TIMESTAMPTZ,
    failed_login_attempts INT          NOT NULL DEFAULT 0,
    oauth_provider        VARCHAR(50),
    oauth_provider_id     VARCHAR(255),
    profile_picture_url   VARCHAR(255),
    last_login_at         TIMESTAMPTZ,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_users_oauth_provider ON users (oauth_provider, oauth_provider_id)
    WHERE oauth_provider IS NOT NULL;

CREATE TABLE user_roles
(
    user_id UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role    VARCHAR(50) NOT NULL,
    PRIMARY KEY (user_id, role)
);

CREATE TABLE refresh_tokens
(
    id             UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    token          VARCHAR(64) NOT NULL UNIQUE,
    user_id        UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by_ip  VARCHAR(45),
    user_agent     VARCHAR(255),
    revoked        BOOLEAN     NOT NULL DEFAULT FALSE,
    revoked_at     TIMESTAMPTZ,
    revoked_reason VARCHAR(100)
);

CREATE INDEX idx_rt_token ON refresh_tokens (token);
CREATE INDEX idx_rt_user_id ON refresh_tokens (user_id);

CREATE TABLE password_reset_tokens
(
    id         UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    token      VARCHAR(64) NOT NULL UNIQUE,
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    used       BOOLEAN     NOT NULL DEFAULT FALSE,
    token_type VARCHAR(30) NOT NULL DEFAULT 'PASSWORD_RESET'
);
CREATE INDEX idx_prt_token ON password_reset_tokens (token);
CREATE INDEX idx_prt_user_id ON password_reset_tokens (user_id);

CREATE TABLE audit_logs
(
    id         UUID PRIMARY KEY     DEFAULT gen_random_uuid(),

    user_id    UUID,
    user_email VARCHAR(255),
    event_type VARCHAR(60) NOT NULL,
    details    TEXT,
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    failed     BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_al_user_id ON audit_logs (user_id);
CREATE INDEX idx_al_event_type ON audit_logs (event_type);
CREATE INDEX idx_al_created_at ON audit_logs (created_at DESC);

INSERT INTO users (id, email, password_hash, first_name, last_name, email_verified, enabled)
VALUES (gen_random_uuid(),
        'admin@example.com',
        '$2a$12$LQv3c1yqBwEHXP5Zt.tXiOuZkRe.vGr1nLjJT14JlK/rGDq5Z0OJO', -- BCrypt hash of "Admin@12345"
        'Admin',
        'User',
        TRUE,
        TRUE);

INSERT INTO user_roles (user_id, role)
SELECT id, 'ADMIN'
FROM users
WHERE email = 'admin@example.com';

INSERT INTO user_roles (user_id, role)
SELECT id, 'USER'
FROM users
WHERE email = 'admin@example.com';

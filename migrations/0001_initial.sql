CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    normalized_username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    password_hash TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE oauth_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (provider, provider_subject),
    UNIQUE (provider, user_id)
);

CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_digest BLOB NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    revoked_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX sessions_user_expiry ON sessions(user_id, expires_at);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    client_message_id TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE RESTRICT,
    UNIQUE (sender_id, client_message_id)
);

CREATE INDEX messages_history ON messages(id DESC);

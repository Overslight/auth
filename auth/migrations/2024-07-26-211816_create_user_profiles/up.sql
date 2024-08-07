CREATE TABLE users (
    uid UUID PRIMARY KEY,
    metadata JSONB
);

CREATE TABLE email_password_credentials (
    cid UUID PRIMARY KEY,
    uid UUID UNIQUE NOT NULL REFERENCES users ON DELETE RESTRICT,
    email email UNIQUE NOT NULL,
    password text NOT NULL
);

CREATE TABLE credentials (
    uid UUID PRIMARY KEY REFERENCES users ON DELETE RESTRICT,
    email_password UUID REFERENCES email_password_credentials (cid) ON DELETE SET NULL
);
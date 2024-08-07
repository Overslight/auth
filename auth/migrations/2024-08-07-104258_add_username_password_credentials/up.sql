DROP TABLE credentials;

CREATE TABLE username_password_credentials (
    cid UUID PRIMARY KEY,
    uid UUID UNIQUE NOT NULL REFERENCES users ON DELETE RESTRICT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    verified BOOLEAN NOT NULL,
    last_update TIMESTAMP NOT NULL,
    last_authentication TIMESTAMP NOT NULL,
    created TIMESTAMP NOT NULL
);

CREATE TABLE credentials (
    uid UUID PRIMARY KEY REFERENCES users ON DELETE RESTRICT,
    email_password UUID REFERENCES email_password_credentials (cid) ON DELETE SET NULL,
    github_oauth UUID REFERENCES github_oauth_credentials (cid) ON DELETE SET NULL,
    username_password UUID REFERENCES username_password_credentials (cid) ON DELETE SET NULL
);
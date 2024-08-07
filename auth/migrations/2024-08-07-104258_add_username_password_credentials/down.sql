DROP TABLE CREDENTIALS;
DROP TABLE username_password_credentials;

CREATE TABLE credentials (
    uid UUID PRIMARY KEY REFERENCES users ON DELETE RESTRICT,
    email_password UUID REFERENCES email_password_credentials (cid) ON DELETE SET NULL,
    github_oauth UUID REFERENCES github_oauth_credentials (cid) ON DELETE SET NULL
);
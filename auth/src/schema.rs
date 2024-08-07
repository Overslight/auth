// @generated automatically by Diesel CLI.

diesel::table! {
    credentials (uid) {
        uid -> Uuid,
        email_password -> Nullable<Uuid>,
        github_oauth -> Nullable<Uuid>,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    email_password_credentials (cid) {
        cid -> Uuid,
        uid -> Uuid,
        email -> Citext,
        password -> Text,
        verified -> Bool,
        last_update -> Timestamp,
        last_authentication -> Timestamp,
        created -> Timestamp,
    }
}

diesel::table! {
    github_oauth_credentials (cid) {
        cid -> Uuid,
        uid -> Uuid,
        provider_id -> Int4,
        email -> Text,
        last_authentication -> Timestamp,
        created -> Timestamp,
    }
}

diesel::table! {
    users (uid) {
        uid -> Uuid,
        metadata -> Nullable<Jsonb>,
    }
}

diesel::joinable!(credentials -> email_password_credentials (email_password));
diesel::joinable!(credentials -> github_oauth_credentials (github_oauth));
diesel::joinable!(credentials -> users (uid));
diesel::joinable!(email_password_credentials -> users (uid));
diesel::joinable!(github_oauth_credentials -> users (uid));

diesel::allow_tables_to_appear_in_same_query!(
    credentials,
    email_password_credentials,
    github_oauth_credentials,
    users,
);

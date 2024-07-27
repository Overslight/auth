// @generated automatically by Diesel CLI.
diesel::table! {
    credentials (uid) {
        uid -> Uuid,
        email_password -> Nullable<Uuid>,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    email_password_credentials (cid) {
        cid -> Uuid,
        uid -> Uuid,
        email -> Citext,
        password -> Text,
    }
}

diesel::table! {
    users (uid) {
        uid -> Uuid,
        metadata -> Nullable<Jsonb>,
    }
}

diesel::joinable!(credentials -> email_password_credentials (email_password));
diesel::joinable!(credentials -> users (uid));
diesel::joinable!(email_password_credentials -> users (uid));

diesel::allow_tables_to_appear_in_same_query!(credentials, email_password_credentials, users,);

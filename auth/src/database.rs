use diesel::PgConnection;

pub type DatabaseConnection<'a> = &'a mut PgConnection;

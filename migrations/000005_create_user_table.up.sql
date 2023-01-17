CREATE EXTENSION citext;

create table if not exists users(
    id bigserial primary key,
    created_at timestamp(0) with time zone NOT NULL DEFAULT NOW(),
    name text not null,
    email CITEXT UNIQUE NOT NULL,
    password_hash bytea not null,
    activated bool not null,
    version uuid not null
)
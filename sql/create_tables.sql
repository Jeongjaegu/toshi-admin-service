CREATE TABLE IF NOT EXISTS admins (
    token_id VARCHAR PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id VARCHAR PRIMARY KEY,
    token_id VARCHAR,
    created TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() AT TIME ZONE 'utc'),
    refreshed TIMESTAMP WITHOUT TIME ZONE DEFAULT (now() AT TIME ZONE 'utc')
);

UPDATE database_version SET version_number = 0;

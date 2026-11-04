CREATE TYPE threat_severity AS enum('low', 'medium', 'high', 'critical');

CREATE TABLE threats
  (
     md5         VARCHAR(32) PRIMARY KEY,
     name        TEXT NOT NULL,
     description TEXT NOT NULL DEFAULT '',
     severity    THREAT_SEVERITY NOT NULL,
     created_at  TIMESTAMPTZ NOT NULL DEFAULT Now(),
     updated_at  TIMESTAMPTZ NOT NULL DEFAULT Now(),
     CONSTRAINT valid_md5 CHECK(md5 ~* '^[a-f0-9]{32}$')
  );
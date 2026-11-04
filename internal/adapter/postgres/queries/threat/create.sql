INSERT INTO threats (
    md5,
    name,
    description,
    severity
)
VALUES ($1, $2, $3, $4)
RETURNING created_at, updated_at;
UPDATE threats
SET
    name = $2,
    description = $3,
    severity = $4,
    updated_at = NOW()
WHERE md5 = $1
RETURNING created_at, updated_at;
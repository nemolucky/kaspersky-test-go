SELECT
    md5,
    name,
    description,
    severity,
    created_at,
    updated_at
FROM threats
WHERE md5 = $1;
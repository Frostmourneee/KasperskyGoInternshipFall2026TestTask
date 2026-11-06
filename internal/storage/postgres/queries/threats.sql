-- name: GetThreat :one
SELECT md5, name, description, threat_type, severity, file_size, created_at, updated_at
FROM threats
WHERE md5 = sqlc.arg(md5);

-- name: CreateThreat :one
INSERT INTO threats (md5, name, description, threat_type, severity, file_size)
VALUES (
    sqlc.arg(md5), sqlc.arg(name), sqlc.arg(description),
    sqlc.arg(threat_type), sqlc.arg(severity), sqlc.narg(file_size)
)
RETURNING md5, name, description, threat_type, severity, file_size, created_at, updated_at;

-- name: UpdateThreat :one
-- Неизменённые данные сохраняют updated_at; IS DISTINCT FROM учитывает NULL.
UPDATE threats
SET name = sqlc.arg(name),
    description = sqlc.arg(description),
    threat_type = sqlc.arg(threat_type),
    severity = sqlc.arg(severity),
    file_size = sqlc.narg(file_size),
    updated_at = CASE
        WHEN (name, description, threat_type, severity, file_size) IS DISTINCT FROM (
            sqlc.arg(name)::text, sqlc.arg(description)::text,
            sqlc.arg(threat_type)::text, sqlc.arg(severity)::text,
            sqlc.narg(file_size)::bigint
        ) THEN GREATEST(clock_timestamp(), updated_at + INTERVAL '1 microsecond')
        ELSE updated_at
    END
WHERE md5 = sqlc.arg(md5)
RETURNING md5, name, description, threat_type, severity, file_size, created_at, updated_at;

-- +goose Up
CREATE TABLE threats (
    md5 text PRIMARY KEY
        CONSTRAINT threats_md5_check CHECK (md5 ~ '^[a-f0-9]{32}$'),
    name text NOT NULL
        CONSTRAINT threats_name_check CHECK (
            char_length(name) BETWEEN 1 AND 255
            AND btrim(name, E' \t\r\n\f\013') <> ''
        ),
    description text NOT NULL DEFAULT ''
        CONSTRAINT threats_description_check CHECK (char_length(description) <= 2000),
    threat_type text NOT NULL DEFAULT 'unknown'
        CONSTRAINT threats_type_check CHECK (
            threat_type IN ('trojan', 'worm', 'ransomware', 'spyware', 'other', 'unknown')
        ),
    severity text NOT NULL DEFAULT 'unknown'
        CONSTRAINT threats_severity_check CHECK (severity IN ('unknown', 'low', 'medium', 'high')),
    file_size bigint
        CONSTRAINT threats_file_size_check CHECK (file_size >= 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- +goose Down
DROP TABLE threats;

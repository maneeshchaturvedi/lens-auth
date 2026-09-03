CREATE TABLE llmlens.refresh_tokens (
    id uuid NOT NULL DEFAULT extensions.uuid_generate_v4(),
    token_hash varchar(255) NOT NULL,
    user_id uuid NOT NULL,
    license_id uuid NOT NULL,
    device_fingerprint varchar(255),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz DEFAULT now(),
    CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT refresh_tokens_license_id_fkey FOREIGN KEY (license_id)
        REFERENCES llmlens.licenses (id) ON DELETE CASCADE
) TABLESPACE pg_default;

CREATE INDEX idx_refresh_tokens_user ON llmlens.refresh_tokens USING btree (user_id);

CREATE INDEX idx_refresh_tokens_expires ON llmlens.refresh_tokens USING btree (expires_at)
    WHERE revoked_at IS NULL;

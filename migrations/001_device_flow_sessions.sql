CREATE TABLE llmlens.device_flow_sessions (
    id uuid NOT NULL DEFAULT extensions.uuid_generate_v4(),
    device_code varchar(255) NOT NULL,
    user_code varchar(8) NOT NULL,
    device_fingerprint varchar(255),
    device_name varchar(255),
    status varchar(20) NOT NULL DEFAULT 'pending',
    user_id uuid,
    expires_at timestamptz NOT NULL,
    created_at timestamptz DEFAULT now(),
    CONSTRAINT device_flow_sessions_pkey PRIMARY KEY (id),
    CONSTRAINT device_flow_sessions_device_code_key UNIQUE (device_code),
    CONSTRAINT device_flow_sessions_user_code_key UNIQUE (user_code),
    CONSTRAINT device_flow_sessions_status_check CHECK (
        status IN ('pending', 'complete', 'expired')
    )
) TABLESPACE pg_default;

CREATE INDEX idx_device_flow_expires ON llmlens.device_flow_sessions USING btree (expires_at)
    WHERE status = 'pending';

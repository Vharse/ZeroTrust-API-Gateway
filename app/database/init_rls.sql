CREATE TABLE IF NOT EXISTS upstream_services (
    id SERIAL PRIMARY KEY,
    client_org_id UUID NOT NULL,
    service_name VARCHAR(50) NOT NULL,
    upstream_url VARCHAR(500) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_tenant_service UNIQUE (client_org_id, service_name)
);

ALTER TABLE upstream_services ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy ON upstream_services
    USING (client_org_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (client_org_id::text = current_setting('app.current_tenant_id', true));

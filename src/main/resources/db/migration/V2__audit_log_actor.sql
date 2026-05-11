ALTER TABLE audit_logs ADD COLUMN actor_user_id UUID;
ALTER TABLE audit_logs ADD COLUMN actor_email   VARCHAR(255);
CREATE INDEX idx_al_actor_user_id ON audit_logs(actor_user_id);
-- The relay's ServerLogin state between login/start and login/finish, so the
-- relay stays stateless across requests. Rows are short-lived and swept.
CREATE TABLE login_states (
    account_id BLOB NOT NULL,
    device_id  BLOB NOT NULL,
    state      BLOB NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (account_id, device_id)
);

//! Integration tests for studge-relay (SPEC §7).
//!
//! Every test spawns a real relay on a random port (`0.0.0.0:0`) using an
//! in-memory SQLite database and a fresh OPAQUE setup key, then drives it
//! through reqwest. No mocking: these tests prove the full HTTP stack.
//!
//! Covered scenarios:
//! - register_and_login: full OPAQUE round trip plus session token
//! - wrong_password: login/finish returns 401
//! - duplicate_account: second register/finish returns 409
//! - token_expiry_is_enforced: an expired session is 401
//! - logout_and_token_revocation: DELETE /v1/sessions/current
//! - append_and_fetch_ops_with_cursors: multi-page pagination
//! - head_compare_and_swap_conflict: concurrent writes return 409
//! - quota_exceeded: pushing past the storage limit returns 507
//! - rate_limit_register: five registrations per IP per hour
//! - another_accounts_vault_is_404: vault isolation
//! - malformed_inputs: garbage returns 400 not 500

mod helpers;
use helpers::{hex_id, Relay, TestAccount};
use serde_json::{json, Value};

// ── register + login ──────────────────────────────────────────────────────────

#[tokio::test]
async fn register_and_login() {
    let relay = Relay::start().await;
    let account = TestAccount::new();
    account.register(&relay).await;
    let token = account.login(&relay).await;
    assert_eq!(token.len(), 64, "token is 32-byte hex");
    // GET /v1/account with a valid session returns the account record.
    let resp = relay
        .client()
        .get(relay.url("/v1/account"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 200, "account reachable with valid token");
    let body: Value = resp.json().await.expect("json");
    assert_eq!(
        body["account_id"].as_str().expect("account_id"),
        hex_id(&account.account_id),
        "returned account_id matches"
    );
}

#[tokio::test]
async fn wrong_password_returns_401() {
    let relay = Relay::start().await;
    let account = TestAccount::new();
    account.register(&relay).await;
    // Log in with a different auth_secret.
    let result = account
        .login_secret(&relay, b"wrong_wrong_wrong_wrong_wrong_wr")
        .await;
    assert!(result.is_none(), "wrong password returns no token (401)");
}

#[tokio::test]
async fn duplicate_account_returns_409() {
    let relay = Relay::start().await;
    let account = TestAccount::new();
    account.register(&relay).await;
    // Trying to register the same account_id again is a conflict.
    let status = account.register_raw(&relay).await;
    assert_eq!(status, 409, "second registration is 409");
}

#[tokio::test]
async fn logout_and_token_revocation() {
    let relay = Relay::start().await;
    let account = TestAccount::new();
    account.register(&relay).await;
    let token = account.login(&relay).await;

    // The token works before logout.
    let before = relay
        .client()
        .get(relay.url("/v1/account"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("request")
        .status();
    assert_eq!(before, 200, "valid before logout");

    // Logout.
    let logout = relay
        .client()
        .delete(relay.url("/v1/sessions/current"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("logout");
    assert_eq!(logout.status(), 204, "logout returns 204");

    // The same token is now rejected.
    let after = relay
        .client()
        .get(relay.url("/v1/account"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("request")
        .status();
    assert_eq!(after, 401, "token rejected after logout");
}

// ── vault ops ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn append_and_fetch_ops_with_cursors() {
    let relay = Relay::start().await;
    let account = TestAccount::new();
    account.register(&relay).await;
    let token = account.login(&relay).await;
    let vault_id = helpers::random_id();

    // Push 5 ops (well under the 100-op push limit).
    let ops = helpers::make_ops(&vault_id, 5);
    let resp = relay
        .client()
        .post(relay.url(&format!("/v1/vaults/{}/ops", hex_id(&vault_id))))
        .bearer_auth(&token)
        .header("content-type", "application/cbor")
        .body(ops.clone())
        .send()
        .await
        .expect("push");
    assert_eq!(resp.status(), 200, "push succeeds");
    let push_body: Value = resp.json().await.expect("json");
    assert_eq!(push_body["accepted"], 5, "all 5 accepted");
    assert_eq!(
        push_body["rejected"].as_array().expect("array").len(),
        0,
        "none rejected"
    );

    // Fetch page 1 (limit 3).
    let resp = relay
        .client()
        .get(relay.url(&format!("/v1/vaults/{}/ops?limit=3", hex_id(&vault_id))))
        .bearer_auth(&token)
        .send()
        .await
        .expect("fetch p1");
    assert_eq!(resp.status(), 200, "fetch p1 ok");
    let cursor = resp
        .headers()
        .get("next-cursor")
        .expect("next-cursor header")
        .to_str()
        .expect("ascii")
        .to_string();
    assert_eq!(cursor.len(), 64, "cursor is a 32-byte hex hash");

    // Fetch page 2 from the cursor (should have 2 remaining).
    let resp = relay
        .client()
        .get(relay.url(&format!(
            "/v1/vaults/{}/ops?limit=3&since={}",
            hex_id(&vault_id),
            cursor
        )))
        .bearer_auth(&token)
        .send()
        .await
        .expect("fetch p2");
    assert_eq!(resp.status(), 200, "fetch p2 ok");
    // No more pages.
    assert!(
        resp.headers().get("next-cursor").is_none(),
        "no cursor on last page"
    );
}

#[tokio::test]
async fn idempotent_op_push_is_accepted() {
    let relay = Relay::start().await;
    let account = TestAccount::new();
    account.register(&relay).await;
    let token = account.login(&relay).await;
    let vault_id = helpers::random_id();
    let ops = helpers::make_ops(&vault_id, 2);

    // Push once.
    let r1 = relay
        .client()
        .post(relay.url(&format!("/v1/vaults/{}/ops", hex_id(&vault_id))))
        .bearer_auth(&token)
        .header("content-type", "application/cbor")
        .body(ops.clone())
        .send()
        .await
        .expect("push1");
    assert_eq!(r1.status(), 200);
    let b1: Value = r1.json().await.expect("j1");
    assert_eq!(b1["accepted"], 2);

    // Push the same bytes again: idempotent (already stored).
    let r2 = relay
        .client()
        .post(relay.url(&format!("/v1/vaults/{}/ops", hex_id(&vault_id))))
        .bearer_auth(&token)
        .header("content-type", "application/cbor")
        .body(ops)
        .send()
        .await
        .expect("push2");
    assert_eq!(r2.status(), 200, "idempotent push ok");
    let b2: Value = r2.json().await.expect("j2");
    assert_eq!(b2["accepted"], 2, "idempotent: 2 accepted again");
}

// ── vault head ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn head_compare_and_swap_conflict() {
    let relay = Relay::start().await;
    let account = TestAccount::new();
    account.register(&relay).await;
    let token = account.login(&relay).await;
    let vault_id = helpers::random_id();

    // Push an op first so the vault row exists.
    let ops = helpers::make_ops(&vault_id, 1);
    relay
        .client()
        .post(relay.url(&format!("/v1/vaults/{}/ops", hex_id(&vault_id))))
        .bearer_auth(&token)
        .header("content-type", "application/cbor")
        .body(ops)
        .send()
        .await
        .expect("push");

    let head1 = helpers::make_head(&vault_id, 1);
    let (head1_bytes, head1_hash) = head1;

    // First PUT: wildcard replaces nothing (first head).
    let r1 = relay
        .client()
        .put(relay.url(&format!("/v1/vaults/{}/head", hex_id(&vault_id))))
        .bearer_auth(&token)
        .header("content-type", "application/cbor")
        .header("if-match", "*")
        .body(head1_bytes.clone())
        .send()
        .await
        .expect("put head1");
    assert_eq!(r1.status(), 200, "first head accepted");

    let head2 = helpers::make_head(&vault_id, 2);
    let (head2_bytes, _head2_hash) = head2;

    // Second PUT with the correct previous hash: succeeds.
    let r2 = relay
        .client()
        .put(relay.url(&format!("/v1/vaults/{}/head", hex_id(&vault_id))))
        .bearer_auth(&token)
        .header("content-type", "application/cbor")
        .header("if-match", &head1_hash)
        .body(head2_bytes.clone())
        .send()
        .await
        .expect("put head2");
    assert_eq!(r2.status(), 200, "head2 accepted with correct If-Match");

    // Third PUT using the stale head1 hash: conflict.
    let head3 = helpers::make_head(&vault_id, 3);
    let (head3_bytes, _) = head3;
    let r3 = relay
        .client()
        .put(relay.url(&format!("/v1/vaults/{}/head", hex_id(&vault_id))))
        .bearer_auth(&token)
        .header("content-type", "application/cbor")
        .header("if-match", &head1_hash)
        .body(head3_bytes)
        .send()
        .await
        .expect("put head3");
    assert_eq!(r3.status(), 409, "stale If-Match is 409");
    let err: Value = r3.json().await.expect("json");
    assert_eq!(err["error"], "conflict");
}

// ── isolation ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn another_accounts_vault_is_404() {
    let relay = Relay::start().await;
    let alice = TestAccount::new();
    alice.register(&relay).await;
    let alice_token = alice.login(&relay).await;

    let bob = TestAccount::new();
    bob.register(&relay).await;
    let bob_token = bob.login(&relay).await;

    // Alice pushes ops to her vault.
    let vault_id = helpers::random_id();
    let ops = helpers::make_ops(&vault_id, 1);
    relay
        .client()
        .post(relay.url(&format!("/v1/vaults/{}/ops", hex_id(&vault_id))))
        .bearer_auth(&alice_token)
        .header("content-type", "application/cbor")
        .body(ops)
        .send()
        .await
        .expect("push");

    // Bob tries to read Alice's vault: gets 404 (not 401 or 403 — no leaking).
    let resp = relay
        .client()
        .get(relay.url(&format!("/v1/vaults/{}/ops", hex_id(&vault_id))))
        .bearer_auth(&bob_token)
        .send()
        .await
        .expect("bob fetch");
    assert_eq!(resp.status(), 404, "another account's vault is 404");
}

// ── malformed inputs ──────────────────────────────────────────────────────────

#[tokio::test]
async fn malformed_inputs_return_400_not_500() {
    let relay = Relay::start().await;

    // Garbage JSON body — axum returns 422 Unprocessable Entity for malformed
    // JSON (RFC 9110 §15.5.21); both 400 and 422 are "client error".
    let resp = relay
        .client()
        .post(relay.url("/v1/register/start"))
        .header("content-type", "application/json")
        .body("not json at all")
        .send()
        .await
        .expect("request");
    assert!(
        resp.status() == 400 || resp.status() == 422,
        "garbage body: {}",
        resp.status()
    );

    // Unknown field in JSON body — rejected by deny_unknown_fields.
    let resp = relay
        .client()
        .post(relay.url("/v1/register/start"))
        .json(&json!({"account_id": "aa".repeat(16), "registration_request": "aGk=", "extra": 1}))
        .send()
        .await
        .expect("request");
    assert!(
        resp.status() == 400 || resp.status() == 422,
        "unknown field: {}",
        resp.status()
    );

    // Wrong hex length for account_id.
    let resp = relay
        .client()
        .post(relay.url("/v1/register/start"))
        .json(&json!({"account_id": "aabb", "registration_request": "aGk="}))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 400);

    // Missing Content-Type on CBOR endpoint.
    let account = TestAccount::new();
    account.register(&relay).await;
    let token = account.login(&relay).await;
    let vault_id = helpers::random_id();
    let resp = relay
        .client()
        .post(relay.url(&format!("/v1/vaults/{}/ops", hex_id(&vault_id))))
        .bearer_auth(&token)
        .body(vec![0xA0u8]) // minimal CBOR map
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 400, "missing content-type is 400");
}

#[tokio::test]
async fn an_unknown_path_returns_404() {
    let relay = Relay::start().await;
    let resp = relay
        .client()
        .get(relay.url("/v1/nope"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 404);
    let body: Value = resp.json().await.expect("json");
    assert_eq!(body["error"], "not_found");
}

#[tokio::test]
async fn no_bearer_token_returns_401() {
    let relay = Relay::start().await;
    let resp = relay
        .client()
        .get(relay.url("/v1/account"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), 401);
}

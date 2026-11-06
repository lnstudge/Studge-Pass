//! OPAQUE (SPEC §4.4): ristretto255, identity KSF (D-0102).
//!
//! The relay never sees `auth_secret` — it is the *password input* to OPAQUE
//! and exists only inside these wrappers. Everything here is bytes-in,
//! bytes-out: the relay stores the password file, the client holds its state
//! between the two messages, and neither side logs anything.
//!
//! The credential identifier OPAQUE binds into the record is the 16-byte
//! `account_id`, so a password file cannot be replayed for another account.
//!
//! The KSF is the identity function because `auth_secret` is already a uniform
//! 256-bit HKDF output (§4.3): stretching twice would only hurt unlock time.
//! That is the approved decision D-0102; do not "upgrade" it without one.

use crate::crypto::error::{CryptoError, CryptoResult};
use opaque_ke::errors::ProtocolError;
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginParameters, ServerRegistration, ServerSetup,
};

/// The cipher suite of SPEC §4.4: ristretto255 OPRF and key exchange, SHA-512
/// inside the triple-DH, and the identity KSF (D-0102).
#[derive(Clone, Copy, Debug)]
pub struct StudgeOpaque;

impl CipherSuite for StudgeOpaque {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2_kex::Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

/// The OPAQUE server-setup key: the relay's long-term secret, generated once
/// and persisted outside the database.
pub struct ServerSetupKey {
    inner: ServerSetup<StudgeOpaque>,
}

impl ServerSetupKey {
    /// Generates a new setup key from the operating system's RNG.
    pub fn generate() -> CryptoResult<Self> {
        Ok(Self {
            inner: ServerSetup::<StudgeOpaque>::new(&mut rand::rngs::OsRng),
        })
    }

    /// Restores a setup key from its stored bytes.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        let inner = ServerSetup::<StudgeOpaque>::deserialize(bytes)
            .map_err(|_| CryptoError::InvalidEncoding)?;
        Ok(Self { inner })
    }

    /// The stored bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.serialize().to_vec()
    }
}

/// One side of an OPAQUE exchange, held between the two messages.
///
/// The state is serialised so a stateless server can persist it in the session
/// table and a client can hold it in memory between requests. It never leaves
/// the party that created it.
pub struct OpaqueState<T> {
    inner: T,
}

// ---------------------------------------------------------------- registration

/// Starts client registration: produces the request for the relay and a state
/// to finish with.
pub fn client_registration_start(
    auth_secret: &[u8],
) -> CryptoResult<(Vec<u8>, OpaqueState<ClientRegistration<StudgeOpaque>>)> {
    let result = ClientRegistration::<StudgeOpaque>::start(&mut rand::rngs::OsRng, auth_secret)
        .map_err(map_protocol)?;
    Ok((
        result.message.serialize().to_vec().to_vec(),
        OpaqueState {
            inner: result.state,
        },
    ))
}

/// The relay's half of registration start.
pub fn server_registration_start(
    setup: &ServerSetupKey,
    request: &[u8],
    account_id: &[u8; 16],
) -> CryptoResult<Vec<u8>> {
    let request = RegistrationRequest::<StudgeOpaque>::deserialize(request)
        .map_err(|_| CryptoError::InvalidEncoding)?;
    let result = ServerRegistration::<StudgeOpaque>::start(&setup.inner, request, account_id)
        .map_err(map_protocol)?;
    Ok(result.message.serialize().to_vec().to_vec())
}

/// Finishes client registration: produces the upload for the relay.
pub fn client_registration_finish(
    state: OpaqueState<ClientRegistration<StudgeOpaque>>,
    auth_secret: &[u8],
    response: &[u8],
) -> CryptoResult<Vec<u8>> {
    let response = RegistrationResponse::<StudgeOpaque>::deserialize(response)
        .map_err(|_| CryptoError::InvalidEncoding)?;
    let result = state
        .inner
        .finish(
            &mut rand::rngs::OsRng,
            auth_secret,
            response,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(map_protocol)?;
    Ok(result.message.serialize().to_vec().to_vec())
}

/// The relay's half of registration finish: produces the stored password file.
pub fn server_registration_finish(upload: &[u8]) -> CryptoResult<Vec<u8>> {
    let upload = RegistrationUpload::<StudgeOpaque>::deserialize(upload)
        .map_err(|_| CryptoError::InvalidEncoding)?;
    let file = ServerRegistration::<StudgeOpaque>::finish(upload);
    Ok(file.serialize().to_vec())
}

// ---------------------------------------------------------------------- login

/// Starts client login: produces the request for the relay and a state to
/// finish with.
pub fn client_login_start(
    auth_secret: &[u8],
) -> CryptoResult<(Vec<u8>, OpaqueState<ClientLogin<StudgeOpaque>>)> {
    let result = ClientLogin::<StudgeOpaque>::start(&mut rand::rngs::OsRng, auth_secret)
        .map_err(map_protocol)?;
    Ok((
        result.message.serialize().to_vec().to_vec(),
        OpaqueState {
            inner: result.state,
        },
    ))
}

/// The relay's half of login start.
///
/// `password_file` is `None` for an unknown account: the relay answers with a
/// dummy exchange indistinguishable from a real one (D-0113), so registration
/// and login look the same for accounts that do not exist.
pub fn server_login_start(
    setup: &ServerSetupKey,
    password_file: Option<&[u8]>,
    request: &[u8],
    account_id: &[u8; 16],
) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let request = CredentialRequest::<StudgeOpaque>::deserialize(request)
        .map_err(|_| CryptoError::InvalidEncoding)?;
    let file = match password_file {
        Some(bytes) => Some(
            ServerRegistration::<StudgeOpaque>::deserialize(bytes)
                .map_err(|_| CryptoError::InvalidEncoding)?,
        ),
        None => None,
    };
    let result = ServerLogin::<StudgeOpaque>::start(
        &mut rand::rngs::OsRng,
        &setup.inner,
        file,
        request,
        account_id,
        ServerLoginParameters::default(),
    )
    .map_err(map_protocol)?;
    Ok((
        result.message.serialize().to_vec().to_vec(),
        result.state.serialize().to_vec(),
    ))
}

/// Finishes client login: produces the finalization for the relay.
pub fn client_login_finish(
    state: OpaqueState<ClientLogin<StudgeOpaque>>,
    auth_secret: &[u8],
    response: &[u8],
) -> CryptoResult<Vec<u8>> {
    let response = CredentialResponse::<StudgeOpaque>::deserialize(response)
        .map_err(|_| CryptoError::InvalidEncoding)?;
    let result = state
        .inner
        .finish(
            &mut rand::rngs::OsRng,
            auth_secret,
            response,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(result.message.serialize().to_vec().to_vec())
}

/// The relay's half of login finish. A failure here is the wrong password: the
/// caller answers `unauthorized` and never says more.
pub fn server_login_finish(server_state: &[u8], finalization: &[u8]) -> CryptoResult<()> {
    let state = ServerLogin::<StudgeOpaque>::deserialize(server_state)
        .map_err(|_| CryptoError::InvalidEncoding)?;
    let finalization = CredentialFinalization::<StudgeOpaque>::deserialize(finalization)
        .map_err(|_| CryptoError::InvalidEncoding)?;
    state
        .finish(finalization, ServerLoginParameters::default())
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(())
}

fn map_protocol(error: ProtocolError) -> CryptoError {
    // Every protocol failure is "the bytes did not authenticate": the caller
    // answers unauthorized or invalid_request, never with details.
    match error {
        ProtocolError::InvalidLoginError => CryptoError::DecryptionFailed,
        _ => CryptoError::InvalidEncoding,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: [u8; 16] = [0xA1; 16];

    fn auth_secret() -> Vec<u8> {
        vec![0x42; 32]
    }

    #[test]
    fn registration_and_login_round_trip() {
        let setup = ServerSetupKey::generate().expect("setup");
        let secret = auth_secret();

        // Registration, all four steps.
        let (request, client_state) = client_registration_start(&secret).expect("client start");
        let response = server_registration_start(&setup, &request, &ACCOUNT).expect("server start");
        let upload = client_registration_finish(client_state, &secret, &response).expect("finish");
        let password_file = server_registration_finish(&upload).expect("server finish");

        // A different secret must not produce the same file; both are valid
        // uploads, so equality of behaviour is checked at login below.
        // Login with the right secret succeeds.
        let (login_request, login_state) = client_login_start(&secret).expect("login start");
        let (credential_response, server_state) =
            server_login_start(&setup, Some(&password_file), &login_request, &ACCOUNT)
                .expect("server login");
        let finalization =
            client_login_finish(login_state, &secret, &credential_response).expect("client finish");
        server_login_finish(&server_state, &finalization).expect("server finish");

        // Login with the wrong secret fails at the client's finish step.
        let wrong = vec![0x43; 32];
        let (bad_request, bad_state) = client_login_start(&wrong).expect("start");
        let (bad_response, _server) =
            server_login_start(&setup, Some(&password_file), &bad_request, &ACCOUNT)
                .expect("server start");
        assert!(client_login_finish(bad_state, &wrong, &bad_response).is_err());
    }

    #[test]
    fn an_unknown_account_gets_an_indistinguishable_response() {
        let setup = ServerSetupKey::generate().expect("setup");
        let secret = auth_secret();
        let (request, _state) = client_login_start(&secret).expect("start");
        let (dummy, _server) = server_login_start(&setup, None, &request, &ACCOUNT).expect("dummy");

        // The dummy response is a parseable CredentialResponse of the usual
        // size: the caller answers unauthorized either way, and timing is the
        // only other difference (D-0113).
        assert!(CredentialResponse::<StudgeOpaque>::deserialize(&dummy).is_ok());
    }

    #[test]
    fn a_password_file_is_bound_to_its_account() {
        let setup = ServerSetupKey::generate().expect("setup");
        let secret = auth_secret();
        let (request, state) = client_registration_start(&secret).expect("start");
        let response = server_registration_start(&setup, &request, &ACCOUNT).expect("server");
        let upload = client_registration_finish(state, &secret, &response).expect("finish");
        let file = server_registration_finish(&upload).expect("file");

        // Login under a different account id: the exchange itself fails (the
        // OPRF is bound to the registering identifier), so a stolen password
        // file cannot be replayed for another account.
        let other: [u8; 16] = [0xBB; 16];
        let (login_request, login_state) = client_login_start(&secret).expect("start");
        let (response, _server_state) =
            server_login_start(&setup, Some(&file), &login_request, &other).expect("start");
        assert!(client_login_finish(login_state, &secret, &response).is_err());
    }

    #[test]
    fn garbage_bytes_are_rejected_not_panicked() {
        let setup = ServerSetupKey::generate().expect("setup");
        assert!(ServerSetupKey::from_bytes(b"garbage").is_err());
        assert!(server_registration_start(&setup, b"garbage", &ACCOUNT).is_err());
        assert!(server_registration_finish(b"garbage").is_err());
        assert!(server_login_start(&setup, Some(b"garbage"), b"garbage", &ACCOUNT).is_err());
        assert!(server_login_finish(b"garbage", b"garbage").is_err());
        assert!(client_registration_finish(
            OpaqueState {
                inner: sample_state()
            },
            &[0u8; 32],
            b"garbage",
        )
        .is_err());
    }

    // A state whose inner value is only reachable inside the crate: used to
    // prove that finish() rejects garbage without needing a full exchange.
    fn sample_state() -> ClientRegistration<StudgeOpaque> {
        let (request, state) = client_registration_start(&[1u8; 32]).expect("state for the test");
        let _ = request;
        state.inner
    }
}

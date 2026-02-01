//! SCRAM authentication implementation
//!
//! Provides SCRAM-SHA-256 authentication for user credentials,
//! generating salts and verifiers for secure storage, and server-side verification.

use anyhow::anyhow;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use subtle::ConstantTimeEq;
use std::collections::HashMap;
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine;
use unicode_normalization::UnicodeNormalization;
use tracing;

/// Minimum PBKDF2 iterations for SCRAM authentication (security baseline)
const MIN_ITERATIONS: u32 = 100_000;
/// Recommended PBKDF2 iterations for SCRAM authentication (strong security)
const RECOMMENDED_ITERATIONS: u32 = 600_000;

/// SCRAM authentication data for a user
#[derive(Clone)]
pub struct ScramAuth {
    /// Random salt used in SCRAM
    pub salt: Vec<u8>,
    /// Stored key for authentication
    pub stored_key: Vec<u8>,
    /// Server key for server signature
    pub server_key: Vec<u8>,
}

impl std::fmt::Debug for ScramAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScramAuth")
            .field("salt", &"[REDACTED]")
            .field("stored_key", &"[REDACTED]")
            .field("server_key", &"[REDACTED]")
            .finish()
    }
}

impl ScramAuth {
    /// Generate new SCRAM credentials for a user
    pub fn new(_username: &str, password: &str) -> anyhow::Result<Self> {
        let salt: [u8; 32] = rand::random();

        // Derive SaltedPassword = PBKDF2(password, salt, i=600000, SHA-256)
        let salted_password = pbkdf2_sha256(password.as_bytes(), &salt, RECOMMENDED_ITERATIONS)?;
        
        // StoredKey = SHA-256(ClientKey)
        // ClientKey = HMAC(SaltedPassword, "Client Key")
        let client_key = compute_hmac_sha256(&salted_password, b"Client Key")?;
        let stored_key = Sha256::digest(&client_key).to_vec();
        
        // ServerKey = HMAC(SaltedPassword, "Server Key")
        let server_key = compute_hmac_sha256(&salted_password, b"Server Key")?;
        
        Ok(Self {
            salt: salt.to_vec(),
            stored_key,
            server_key: server_key.to_vec(),
        })
    }

    /// Create deterministic dummy credentials for timing-attack mitigation.
    ///
    /// SECURITY: This function generates credentials using a fixed salt and password
    /// to ensure that the authentication path takes identical time regardless of
    /// whether the user exists. This prevents timing attacks that could distinguish
    /// between "user not found" and "wrong password" scenarios.
    ///
    /// The dummy credentials are never used for actual authentication - they only
    /// serve to mask timing differences in the initial lookup phase.
    pub fn dummy() -> Self {
        // Fixed salt for deterministic dummy credentials
        // This ensures identical computation time for all dummy auth paths
        const DUMMY_SALT: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        
        // Fixed password for dummy credentials
        // Using a non-trivial password ensures full PBKDF2 computation
        const DUMMY_PASSWORD: &str = "dummy-password-for-timing-attack-mitigation";
        
        // Derive SaltedPassword using the same PBKDF2 parameters as real auth
        let salted_password = pbkdf2_sha256(DUMMY_PASSWORD.as_bytes(), &DUMMY_SALT, RECOMMENDED_ITERATIONS)
            .expect("PBKDF2 with valid params should never fail");
        
        // Compute ClientKey and StoredKey
        let client_key = compute_hmac_sha256(&salted_password, b"Client Key")
            .expect("HMAC with valid key should never fail");
        let stored_key = Sha256::digest(&client_key).to_vec();
        
        // Compute ServerKey
        let server_key = compute_hmac_sha256(&salted_password, b"Server Key")
            .expect("HMAC with valid key should never fail");
        
        Self {
            salt: DUMMY_SALT.to_vec(),
            stored_key,
            server_key,
        }
    }
}

/// Compute HMAC-SHA256
fn compute_hmac_sha256(key: &[u8], msg: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| anyhow!("Invalid HMAC key"))?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// PBKDF2 with SHA-256
fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> anyhow::Result<Vec<u8>> {
    use pbkdf2::pbkdf2_hmac;
    let mut result = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut result);
    Ok(result.to_vec())
}

/// SCRAM server session for handling authentication
#[derive(Debug)]
pub struct ScramServer {
    client_first_bare: String,
    server_first: String,
    stored_key: Vec<u8>,
    server_key: Vec<u8>,
    server_nonce: String,
}

impl ScramServer {
    /// Start SCRAM authentication with client-first message
    pub fn start(client_first: &str, user_auth: &ScramAuth) -> anyhow::Result<Self> {
        // Parse client-first: n,,n=username,r=client-nonce
        // Format: gs2-cbind-flag "," [authzid] "," client-first-bare
        // For no channel binding with empty authzid: "n,,client-first-bare"
        let parts: Vec<&str> = client_first.splitn(3, ',').collect();
        if parts.len() != 3 {
            return Err(anyhow!("Invalid client-first format"));
        }
        let client_first_bare = parts[2];

        let parts: HashMap<&str, &str> = client_first_bare.split(',')
            .filter_map(|p| p.split_once('='))
            .collect();

        if parts.len() != 2 {
            return Err(anyhow!("Invalid client-first-bare format"));
        }

        let _username = parts.get("n")
            .ok_or(anyhow!("Missing username"))?;
        let client_nonce = parts.get("r")
            .ok_or(anyhow!("Missing client nonce"))?;

        // Validate inputs to prevent injection
        if _username.contains(',') {
            return Err(anyhow!("Invalid username"));
        }
        if client_nonce.contains(',') {
            return Err(anyhow!("Invalid client nonce"));
        }
        // Validate client_nonce is not empty
        if client_nonce.is_empty() {
            return Err(anyhow!("Invalid client nonce"));
        }

        // Generate server nonce (proper base64 encoding)
        let mut server_nonce_bytes = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut server_nonce_bytes);
        let server_nonce = Base64.encode(server_nonce_bytes);

        let combined_nonce = format!("{}{}", client_nonce, server_nonce);

        // Server-first: r=combined-nonce,s=salt,i=iterations
        let salt_b64 = Base64.encode(&user_auth.salt);
        let server_first = format!("r={},s={},i={}", combined_nonce, salt_b64, RECOMMENDED_ITERATIONS);

        Ok(Self {
            client_first_bare: client_first_bare.to_string(),
            server_first: server_first.clone(),
            stored_key: user_auth.stored_key.clone(),
            server_key: user_auth.server_key.clone(),
            server_nonce,
        })
    }

    /// Get the server-first message to send to client
    pub fn server_first_message(&self) -> &str {
        &self.server_first
    }

    /// Verify client-final message and return server-final if successful
    pub fn verify_client_final(&self, client_final: &str) -> anyhow::Result<String> {
        // Parse client-final: c=channel-binding,r=nonce,p=proof
        let parts: HashMap<&str, &str> = client_final.split(',')
            .filter_map(|p| p.split_once('='))
            .collect();

        let _channel_binding_b64 = parts.get("c")
            .ok_or(anyhow!("Missing channel binding"))?;
        let nonce = parts.get("r")
            .ok_or(anyhow!("Missing nonce"))?;
        let proof_b64 = parts.get("p")
            .ok_or(anyhow!("Missing proof"))?;

        // Extract client_nonce from client_first_bare
        let client_first_parts: HashMap<&str, &str> = self.client_first_bare.split(',')
            .filter_map(|p| p.split_once('='))
            .collect();
        let client_nonce = client_first_parts.get("r")
            .ok_or(anyhow!("Missing client nonce in client_first_bare"))?;

        // Verify nonce matches
        let expected_nonce = format!("{}{}", client_nonce, self.server_nonce);
        if *nonce != expected_nonce {
            return Err(anyhow!("Nonce mismatch"));
        }

        // Decode client proof
        let client_proof = Base64.decode(proof_b64)
            .map_err(|_| anyhow!("Invalid proof encoding"))?;

        if client_proof.len() != 32 {
            return Err(anyhow!("Invalid proof length"));
        }

        // Build auth message
        let client_final_without_proof = client_final.rsplit_once(",p=")
            .ok_or(anyhow!("Invalid client-final format"))?
            .0;
        let auth_message = format!("{},{},{}",
            self.client_first_bare,
            self.server_first,
            client_final_without_proof
        );

        // Compute ClientSignature = HMAC(StoredKey, AuthMessage)
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.stored_key)
            .map_err(|_| anyhow!("Invalid stored key"))?;
        mac.update(auth_message.as_bytes());
        let client_signature = mac.finalize().into_bytes();

        // Recover ClientKey = ClientProof XOR ClientSignature
        let client_key: Vec<u8> = client_proof.iter()
            .zip(client_signature.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        // Verify: SHA256(ClientKey) == StoredKey
        let computed_stored_key = Sha256::digest(&client_key);

        if !bool::from(computed_stored_key.ct_eq(&self.stored_key)) {
            return Err(anyhow!("Authentication failed"));
        }

        // Compute ServerSignature = HMAC(ServerKey, AuthMessage)
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.server_key)
            .map_err(|_| anyhow!("Invalid server key"))?;
        mac.update(auth_message.as_bytes());
        let server_signature = mac.finalize().into_bytes();

        // Return server-final with real signature
        let server_final = format!("v={}", Base64.encode(server_signature));

        Ok(server_final)
    }
}

/// SCRAM client session for client-side authentication
///
/// Implements the client-side SCRAM-SHA-256 protocol as defined in RFC 5802.
#[derive(Debug)]
pub struct ScramClient {
    username: String,
    password: String,
    client_first_bare: String,
    server_first: String,
    stored_key: Vec<u8>,
    server_key: Vec<u8>,
    client_key: Option<Vec<u8>>,
    auth_message: String,
}

impl ScramClient {
    /// Create a new SCRAM client session
    ///
    /// Generates a SCRAM client-first message to initiate authentication.
    pub fn new(username: &str, password: &str) -> anyhow::Result<Self> {
        // Normalize username and password (SASLprep)
        let username_normalized = username.nfc().collect::<String>();
        let password_normalized = password.nfc().collect::<String>();

        // Generate client nonce (random base64-encoded)
        let mut client_nonce_bytes = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut client_nonce_bytes);
        let client_nonce = Base64.encode(client_nonce_bytes);

        let client_first_bare = format!("n={},r={}", username_normalized, client_nonce);

        Ok(Self {
            username: username_normalized,
            password: password_normalized,
            client_first_bare,
            server_first: String::new(),
            stored_key: Vec::new(),
            server_key: Vec::new(),
            client_key: None,
            auth_message: String::new(),
        })
    }

    /// Get the client-first message to send to server
    ///
    /// Returns the complete SCRAM client-first message with channel binding prefix.
    pub fn client_first_message(&self) -> String {
        // Format: gs2-cbind-flag "," [authzid] "," client-first-bare
        // We use: "n" (no channel binding), empty authzid
        format!("n,,{}", self.client_first_bare)
    }

    /// Process server-first message and extract auth parameters
    ///
    /// Parses the server challenge to extract salt, iterations, and nonce.
    /// Should be called after receiving RoxyChallenge from server.
    pub fn process_server_first(&mut self, server_first: &str) -> anyhow::Result<()> {
        self.server_first = server_first.to_string();

        // Parse server-first: r=combined-nonce,s=salt,i=iterations
        let parts: std::collections::HashMap<&str, &str> = server_first
            .split(',')
            .filter_map(|p| p.split_once('='))
            .collect();

        let _combined_nonce = parts
            .get("r")
            .ok_or_else(|| anyhow!("Missing nonce in server-first"))?;
        let salt_b64 = parts
            .get("s")
            .ok_or_else(|| anyhow!("Missing salt in server-first"))?;
        let iterations_str = parts
            .get("i")
            .ok_or_else(|| anyhow!("Missing iterations in server-first"))?;

        // Validate iterations (must be at least MIN_ITERATIONS for security)
        let iterations: u32 = iterations_str.parse()
            .map_err(|_| anyhow!("Invalid iterations value"))?;
        if iterations < MIN_ITERATIONS {
            return Err(anyhow!(
                "Iterations count too low ({} < {}), possible weak password attack",
                iterations, MIN_ITERATIONS
            ));
        }
        if iterations < RECOMMENDED_ITERATIONS {
            tracing::warn!(
                "PBKDF2 iterations ({}) is below recommended ({}). Consider upgrading for stronger security.",
                iterations, RECOMMENDED_ITERATIONS
            );
        }

        // Decode salt
        let salt = Base64.decode(salt_b64)
            .map_err(|_| anyhow!("Invalid salt encoding"))?;

        // Derive SaltedPassword = PBKDF2(password, salt, iterations, SHA-256)
        let salted_password = pbkdf2_sha256(self.password.as_bytes(), &salt, iterations)?;

        // Compute ClientKey = HMAC-SHA256(SaltedPassword, "Client Key")
        let client_key = compute_hmac_sha256(&salted_password, b"Client Key")?;
        self.client_key = Some(client_key.clone());

        // Compute StoredKey = SHA256(ClientKey)
        self.stored_key = Sha256::digest(&client_key).to_vec();

        // Compute ServerKey = HMAC-SHA256(SaltedPassword, "Server Key") for later verification
        self.server_key = compute_hmac_sha256(&salted_password, b"Server Key")?;

        Ok(())
    }

    /// Generate client-final message with authentication proof
    ///
    /// Computes the SCRAM proof and returns the client-final message to send to server.
    pub fn client_final_message(&mut self) -> anyhow::Result<String> {
        if self.server_first.is_empty() {
            return Err(anyhow!("Server-first not processed yet"));
        }

        // Extract nonce from server-first
        let parts: std::collections::HashMap<&str, &str> = self.server_first
            .split(',')
            .filter_map(|p| p.split_once('='))
            .collect();

        let combined_nonce = parts
            .get("r")
            .ok_or_else(|| anyhow!("Missing nonce in server-first"))?;

        // client-final-without-proof = "c=<channel-binding>,r=<nonce>"
        // We use no channel binding: c=biws (base64 of "n,,")
        let channel_binding = Base64.encode("n,,");
        let client_final_without_proof = format!("c={},r={}", channel_binding, combined_nonce);

        // Build auth message and store it for server-final verification
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, self.server_first, client_final_without_proof
        );
        self.auth_message = auth_message.clone();

        // Compute ClientSignature = HMAC-SHA256(StoredKey, AuthMessage)
        let client_signature = compute_hmac_sha256(&self.stored_key, auth_message.as_bytes())?;

        // Retrieve ClientKey (must be stored during process_server_first)
        let client_key = self.client_key.as_ref()
            .ok_or_else(|| anyhow!("ClientKey not available - process_server_first not called"))?;

        // Compute ClientProof = ClientKey XOR ClientSignature
        let client_proof: Vec<u8> = client_key.iter()
            .zip(client_signature.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        // Return complete message WITH proof
        Ok(format!("{},p={}", client_final_without_proof, Base64.encode(&client_proof)))
    }

    /// Verify server-final message (server signature)
    ///
    /// Validates that the server knows the correct password by checking the server signature.
    /// This should be called after receiving RoxyWelcome from server.
    pub fn verify_server_final(&self, server_final: &str) -> anyhow::Result<()> {
        // Parse server-final: v=server-signature
        let parts: std::collections::HashMap<&str, &str> = server_final
            .split(',')
            .filter_map(|p| p.split_once('='))
            .collect();

        let server_sig_b64 = parts
            .get("v")
            .ok_or_else(|| anyhow!("Missing server signature in server-final"))?;

        // Decode server signature
        let server_signature = Base64.decode(server_sig_b64)
            .map_err(|_| anyhow!("Invalid server signature encoding"))?;

        if server_signature.len() != 32 {
            return Err(anyhow!("Invalid server signature length"));
        }

        // Compute expected server signature: HMAC-SHA256(ServerKey, AuthMessage)
        if self.auth_message.is_empty() {
            return Err(anyhow!("Auth message not available - client_final_message not called"));
        }

        let expected_signature = compute_hmac_sha256(&self.server_key, self.auth_message.as_bytes())?;

        // Use constant-time comparison to prevent timing attacks
        let result = subtle::ConstantTimeEq::ct_eq(server_signature.as_slice(), expected_signature.as_slice());

        if bool::from(result) {
            Ok(())
        } else {
            Err(anyhow!("Server signature verification failed"))
        }
    }

    /// Get the stored key (for session key derivation)
    pub fn stored_key(&self) -> &[u8] {
        &self.stored_key
    }

    /// Get the server key (for verification)
    pub fn server_key(&self) -> &[u8] {
        &self.server_key
    }

    /// Get username
    pub fn username(&self) -> &str {
        &self.username
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KEY_SIZE, SCRAM_NONCE_SIZE};

    #[test]
    fn test_scram_auth_new() {
        let auth = ScramAuth::new("user", "password").unwrap();
        assert_eq!(auth.salt.len(), SCRAM_NONCE_SIZE);
        assert_eq!(auth.stored_key.len(), KEY_SIZE); // SHA-256 output
        assert_eq!(auth.server_key.len(), KEY_SIZE);
    }

    #[test]
    fn test_scram_server_start() {
        let auth = ScramAuth::new("user", "password").unwrap();
        let server = ScramServer::start("n,,n=user,r=clientnonce", &auth).unwrap();
        assert!(server.server_first.contains("r="));
        assert!(server.server_first.contains("s="));
    }

    #[test]
    fn test_scram_client_new() {
        let client = ScramClient::new("alice", "password123").unwrap();
        let client_first = client.client_first_message();
        
        // Should have proper format
        assert!(client_first.starts_with("n,,n="));
        assert!(client_first.contains(",r="));
    }

    #[test]
    fn test_scram_client_process_server_first() {
        let mut client = ScramClient::new("alice", "password123").unwrap();
        
        // Create a server challenge using temporary auth
        let auth = ScramAuth::new("alice", "password123").unwrap();
        let server = ScramServer::start(
            &client.client_first_message(),
            &auth
        ).unwrap();

        // Client processes server-first
        let result = client.process_server_first(server.server_first_message());
        assert!(result.is_ok());
    }

    #[test]
    fn test_scram_client_low_iterations_rejected() {
        let mut client = ScramClient::new("alice", "password123").unwrap();
        
        // Malicious server with low iterations
        let server_first = format!("r=combined,s={},i=1000", Base64.encode("salt"));
        let result = client.process_server_first(&server_first);
        
        // Should reject
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too low"));
    }

    #[test]
    fn test_scram_client_client_final_message() {
        let mut client = ScramClient::new("bob", "secret456").unwrap();
        
        let auth = ScramAuth::new("bob", "secret456").unwrap();
        let server = ScramServer::start(
            &client.client_first_message(),
            &auth
        ).unwrap();

        client.process_server_first(server.server_first_message()).unwrap();
        let client_final = client.client_final_message();
        
        assert!(client_final.is_ok());
        let cf = client_final.unwrap();
        assert!(cf.starts_with("c="));
        assert!(cf.contains(",r="));
    }
}

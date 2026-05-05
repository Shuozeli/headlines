//! Concrete `SignatureAlgorithm` implementations and a name-keyed registry.
//!
//! v1 ships with [`Ed25519`] only; the trait + registry shape is what the
//! design doc calls out so adding `EcdsaP256` or `RsaPss2048` later is a
//! one-impl change.

use std::collections::HashMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use headlines_core::{SignatureAlgorithm, VerifyError};

/// Ed25519 signature verifier. Wire format:
///
/// - `public_key`: 32 raw bytes (the standard Ed25519 verifying key).
/// - `signature`:   64 raw bytes (the standard detached Ed25519 signature).
///
/// Both lengths are pinned by the algorithm; non-conforming inputs surface
/// as `MalformedKey` / `MalformedSignature` per the trait contract.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519;

impl Ed25519 {
    pub const NAME: &'static str = "ed25519";
}

impl SignatureAlgorithm for Ed25519 {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn verify(
        &self,
        public_key: &[u8],
        canonical: &[u8],
        signature: &[u8],
    ) -> Result<(), VerifyError> {
        // Decode the verifying key. `from_bytes` returns `Err` for invalid
        // points (off-curve, non-canonical encoding, ...) — surface as
        // MalformedKey.
        let key_bytes: &[u8; 32] = public_key.try_into().map_err(|_| {
            VerifyError::MalformedKey(format!("expected 32 bytes, got {}", public_key.len()))
        })?;
        let verifying_key = VerifyingKey::from_bytes(key_bytes)
            .map_err(|e| VerifyError::MalformedKey(e.to_string()))?;

        // Decode the detached signature. Length-mismatched inputs surface as
        // MalformedSignature; everything else (verification failure) surfaces
        // as BadSignature so we don't leak internal failure modes.
        let sig_bytes: &[u8; 64] = signature
            .try_into()
            .map_err(|_| VerifyError::MalformedSignature)?;
        let sig = Signature::from_bytes(sig_bytes);

        verifying_key
            .verify(canonical, &sig)
            .map_err(|_| VerifyError::BadSignature)
    }
}

/// Name-keyed registry of `SignatureAlgorithm` impls.
///
/// Built once at startup via [`AlgorithmRegistry::new`] / `.with_default()` /
/// `.with(impl)` and shared with `Arc<AlgorithmRegistry>` across the auth
/// pipeline.
pub struct AlgorithmRegistry {
    algos: HashMap<String, Box<dyn SignatureAlgorithm>>,
}

impl AlgorithmRegistry {
    /// Empty registry — no algorithms, every lookup misses.
    pub fn new() -> Self {
        Self {
            algos: HashMap::new(),
        }
    }

    /// Register the v1 default set (`ed25519`).
    pub fn with_default(mut self) -> Self {
        self.algos
            .insert(Ed25519::NAME.to_owned(), Box::new(Ed25519));
        self
    }

    /// Register a custom algorithm. Replaces any existing entry under the
    /// same name.
    pub fn with(mut self, algo: Box<dyn SignatureAlgorithm>) -> Self {
        self.algos.insert(algo.name().to_owned(), algo);
        self
    }

    /// Lookup by `algo` name. `None` if no impl is registered.
    pub fn get(&self, name: &str) -> Option<&dyn SignatureAlgorithm> {
        self.algos.get(name).map(|b| b.as_ref())
    }
}

impl Default for AlgorithmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AlgorithmRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlgorithmRegistry")
            .field("algos", &self.algos.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn ed25519_round_trip_sign_verify_succeeds() {
        // Arrange
        let sk = signing_key();
        let vk = sk.verifying_key();
        let msg = b"HEADLINES-SIGN-V1\nPOST\n/svc/Method\n\n...\n";
        let sig = sk.sign(msg);
        let algo = Ed25519;

        // Act
        let res = algo.verify(vk.as_bytes(), msg, &sig.to_bytes());

        // Assert
        assert!(res.is_ok());
        assert_eq!(algo.name(), "ed25519");
    }

    #[test]
    fn ed25519_verify_with_wrong_key_returns_bad_signature() {
        // Arrange
        let sk = signing_key();
        let other_sk = signing_key();
        let msg = b"test";
        let sig = sk.sign(msg);
        let algo = Ed25519;

        // Act
        let res = algo.verify(other_sk.verifying_key().as_bytes(), msg, &sig.to_bytes());

        // Assert
        assert_eq!(res, Err(VerifyError::BadSignature));
    }

    #[test]
    fn ed25519_verify_rejects_short_public_key_as_malformed_key() {
        // Arrange
        let algo = Ed25519;
        let bad_key = [0u8; 16]; // wrong length
        let sig = [0u8; 64];

        // Act
        let res = algo.verify(&bad_key, b"x", &sig);

        // Assert
        assert!(matches!(res, Err(VerifyError::MalformedKey(_))));
    }

    #[test]
    fn ed25519_verify_returns_error_for_arbitrary_garbage_key() {
        // Arrange — exercise both possible outcomes for an arbitrary 32-byte
        // input that is unlikely to be a valid key paired with the given sig:
        // either `from_bytes` rejects it (`MalformedKey`) or it constructs
        // and verification fails (`BadSignature`). Both branches exit the
        // verify path, which is what we need for coverage.
        let bad = [0xFFu8; 32];
        let sig = [0u8; 64];
        let algo = Ed25519;

        // Act
        let res = algo.verify(&bad, b"x", &sig);

        // Assert
        assert!(res.is_err(), "garbage key must not verify ok: {res:?}");
    }

    #[test]
    fn ed25519_verify_specifically_returns_malformed_key_when_decompression_fails() {
        // Arrange — search the small space of trivial garbage patterns for one
        // `VerifyingKey::from_bytes` rejects, then exercise that branch
        // explicitly. Ed25519 rejects encodings whose recovered y-coordinate
        // is not a valid square / point on the curve.
        let candidates: Vec<[u8; 32]> = (0u32..256)
            .map(|seed| {
                let mut b = [0u8; 32];
                b[0] = seed as u8;
                b[31] = 0x80; // sign bit set; many of these aren't on-curve
                b
            })
            .collect();
        let algo = Ed25519;
        let mut hit_malformed = false;
        for k in &candidates {
            let res = algo.verify(k, b"x", &[0u8; 64]);
            if matches!(res, Err(VerifyError::MalformedKey(_))) {
                hit_malformed = true;
                break;
            }
        }

        // Assert — at least one of the candidates must surface MalformedKey.
        assert!(
            hit_malformed,
            "expected at least one candidate to surface MalformedKey"
        );
    }

    #[test]
    fn ed25519_verify_rejects_short_signature_as_malformed_signature() {
        // Arrange
        let sk = signing_key();
        let vk = sk.verifying_key();
        let algo = Ed25519;
        let bad_sig = [0u8; 16]; // wrong length

        // Act
        let res = algo.verify(vk.as_bytes(), b"x", &bad_sig);

        // Assert
        assert_eq!(res, Err(VerifyError::MalformedSignature));
    }

    #[test]
    fn registry_with_default_returns_ed25519_impl() {
        // Arrange
        let reg = AlgorithmRegistry::new().with_default();

        // Act
        let got = reg.get("ed25519");

        // Assert
        assert!(got.is_some());
        assert_eq!(got.unwrap().name(), "ed25519");
    }

    #[test]
    fn registry_returns_none_for_unknown_algo() {
        // Arrange
        let reg = AlgorithmRegistry::new().with_default();

        // Act
        let got = reg.get("ecdsa-p256");

        // Assert
        assert!(got.is_none());
    }

    #[test]
    fn registry_default_constructor_is_empty() {
        // Arrange / Act
        let reg = AlgorithmRegistry::default();

        // Assert
        assert!(reg.get("ed25519").is_none());
    }

    #[test]
    fn registry_with_custom_algo_lookup_succeeds() {
        // Arrange
        let reg = AlgorithmRegistry::new().with(Box::new(Ed25519));

        // Act
        let got = reg.get("ed25519");

        // Assert
        assert!(got.is_some());
    }

    #[test]
    fn registry_debug_format_lists_registered_names() {
        // Arrange
        let reg = AlgorithmRegistry::new().with_default();

        // Act
        let s = format!("{reg:?}");

        // Assert
        assert!(s.contains("ed25519"), "got: {s}");
    }
}

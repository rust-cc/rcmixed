use rcmixed::traits::{PublicKeyAlgorithm, SignatureAlgorithm};

pub struct Ed25519;

impl SignatureAlgorithm for Ed25519 {
    type SignKey = [u8; 32];
    type VerifyKey = [u8; 32];
    const SIGNATURE_LENGTH: usize = 64;
    const SIGN_KEY_LENGTH: usize = 32;

    fn sign(_plain: &[u8], _sign_key: &Self::SignKey) -> Vec<u8> {
        vec![]
    }

    fn verify(_plain: &[u8], _sign: &[u8], _verify_key: &Self::VerifyKey) -> bool {
        true
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self::SignKey> {
        bincode::deserialize(bytes).ok()
    }

    fn to_bytes(sign_key: &Self::SignKey) -> Vec<u8> {
        bincode::serialize(sign_key).unwrap_or(vec![])
    }
}

pub struct RSA;

impl PublicKeyAlgorithm for RSA {
    type PublicKey = [u8; 32];
    type SecretKey = [u8; 30];
    const SECRET_KEY_LENGTH: usize = 30;

    fn encrypt(_plain: &[u8], _public_key: &Self::PublicKey) -> Vec<u8> {
        vec![]
    }

    fn decrypt(_cipher: &[u8], _secret_key: &Self::SecretKey) -> Vec<u8> {
        vec![]
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self::SecretKey> {
        bincode::deserialize(bytes).ok()
    }

    fn to_bytes(sign_key: &Self::SecretKey) -> Vec<u8> {
        bincode::serialize(sign_key).unwrap_or(vec![])
    }
}

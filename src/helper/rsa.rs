use rand::rngs::OsRng;
use rsa::{hash::Hashes, PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};

use crate::traits::{PublicKeyAlgorithm, SignatureAlgorithm};

pub struct RSA;

impl RSA {
    pub fn genereate() -> (RSAPrivateKey, RSAPublicKey) {
        let mut rng = OsRng::new().expect("no secure randomness available");
        let bits = 2048;
        let key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        (key.clone(), key.to_public_key())
    }
}

impl SignatureAlgorithm for RSA {
    type SignKey = RSAPrivateKey;
    type VerifyKey = RSAPublicKey;
    const SIGNATURE_LENGTH: usize = 2048 / 8;
    const SIGN_KEY_LENGTH: usize = 2048 / 8;

    fn sign(plain: &[u8], sign_key: &Self::SignKey) -> Vec<u8> {
        sign_key
            .sign::<Hashes>(PaddingScheme::PKCS1v15, None, plain)
            .expect("failed to sign")
    }

    fn verify(plain: &[u8], sign: &[u8], verify_key: &Self::VerifyKey) -> bool {
        verify_key
            .verify::<Hashes>(PaddingScheme::PKCS1v15, None, plain, sign)
            .is_ok()
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self::SignKey> {
        bincode::deserialize(bytes).ok()
    }

    fn to_bytes(sign_key: &Self::SignKey) -> Vec<u8> {
        bincode::serialize(sign_key).unwrap()
    }
}

impl PublicKeyAlgorithm for RSA {
    type PublicKey = RSAPublicKey;
    type SecretKey = RSAPrivateKey;
    const SECRET_KEY_LENGTH: usize = 2048 / 8;

    fn encrypt(plain: &[u8], public_key: &Self::PublicKey) -> Vec<u8> {
        let mut rng = OsRng::new().expect("no secure randomness available");

        public_key
            .encrypt(&mut rng, PaddingScheme::PKCS1v15, plain)
            .expect("failed to encrypt")
    }

    fn decrypt(cipher: &[u8], secret_key: &Self::SecretKey) -> Vec<u8> {
        secret_key
            .decrypt(PaddingScheme::PKCS1v15, cipher)
            .expect("failed to decrypt")
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self::SecretKey> {
        bincode::deserialize(bytes).ok()
    }

    fn to_bytes(secret_key: &Self::SecretKey) -> Vec<u8> {
        bincode::serialize(secret_key).unwrap()
    }
}

use serde::de::DeserializeOwned;
use serde::ser::Serialize;

pub trait SignatureAlgorithm {
    type SignKey: Serialize + DeserializeOwned;
    type VerifyKey: Serialize + DeserializeOwned;
    const SIGNATURE_LENGTH: usize;

    fn sign(plain: &[u8], sign_key: &Self::SignKey) -> Vec<u8>;

    fn verify(plain: &[u8], sign: &[u8], verify_key: &Self::VerifyKey) -> bool;
}

pub trait PublicKeyAlgorithm {
    type PublicKey: Serialize + DeserializeOwned;
    type SecretKey: Serialize + DeserializeOwned;

    fn encrypt(plain: &[u8], public_key: &Self::PublicKey) -> Vec<u8>;

    fn decrypt(cipher: &[u8], secret_key: &Self::SecretKey) -> Vec<u8>;
}

pub trait SymmetricAlgorithm {
    type Key: Serialize + DeserializeOwned;
    const KEY_LENGTH: usize;

    fn encrypt(plain: &[u8], session_key: &Self::Key) -> Vec<u8>;

    fn decrypt(cipher: &[u8], session_key: &Self::Key) -> Vec<u8>;

    fn from_bytes(bytes: &[u8]) -> Self::Key;
}

pub trait HashAlgorithm {
    const HASH_LENGTH: usize;

    fn hash(data: &[u8]) -> Vec<u8>;
}

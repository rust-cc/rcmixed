pub trait SignatureAlgorithm {
    type SignKey;
    type VerifyKey;
    const SIGNATURE_LENGTH: usize;
    const SIGN_KEY_LENGTH: usize;

    fn sign(plain: &[u8], sign_key: &Self::SignKey) -> Vec<u8>;

    fn verify(plain: &[u8], sign: &[u8], verify_key: &Self::VerifyKey) -> bool;

    fn from_bytes(bytes: &[u8]) -> Option<Self::SignKey>;

    fn to_bytes(sign_key: &Self::SignKey) -> Vec<u8>;
}

pub trait PublicKeyAlgorithm {
    type PublicKey;
    type SecretKey;
    const SECRET_KEY_LENGTH: usize;

    fn encrypt(plain: &[u8], public_key: &Self::PublicKey) -> Vec<u8>;

    fn decrypt(cipher: &[u8], secret_key: &Self::SecretKey) -> Vec<u8>;

    fn from_bytes(bytes: &[u8]) -> Option<Self::SecretKey>;

    fn to_bytes(secret_key: &Self::SecretKey) -> Vec<u8>;
}

pub trait SymmetricAlgorithm {
    type Key: Default;
    const KEY_LENGTH: usize;

    fn encrypt(plain: &[u8], session_key: &Self::Key) -> Vec<u8>;

    fn decrypt(cipher: &[u8], session_key: &Self::Key) -> Vec<u8>;

    fn from_bytes(bytes: &[u8]) -> Option<Self::Key>;

    fn to_bytes(&self) -> Vec<u8>;
}

pub trait HashAlgorithm {
    const HASH_LENGTH: usize;

    fn hash(data: &[u8]) -> Vec<u8>;
}

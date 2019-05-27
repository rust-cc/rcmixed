use serde::de::DeserializeOwned;
use serde::ser::Serialize;

pub trait SignatureAlgorithm {
    type SignKey: Serialize + DeserializeOwned;
    type VerifyKey: Serialize + DeserializeOwned;

    fn sign(plain: &Vec<u8>, sign_key: &Self::SignKey) -> Vec<u8>;

    fn verify(plain: &Vec<u8>, sign: &Vec<u8>, verify_key: &Self::VerifyKey) -> bool;
}

pub trait PublicKeyAlgorithm {
    type PublicKey: Serialize + DeserializeOwned;
    type SecretKey: Serialize + DeserializeOwned;

    fn encrypt(plain: &Vec<u8>, public_key: &Self::PublicKey) -> Vec<u8>;

    fn decrypt(cipher: &Vec<u8>, secret_key: &Self::SecretKey) -> Vec<u8>;
}

pub trait SymmetricAlgorithm {
    type Key: Serialize + DeserializeOwned;

    fn encrypt(plain: &Vec<u8>, session_key: &Self::Key) -> Vec<u8>;

    fn decrypt(cipher: &Vec<u8>, session_key: &Self::Key) -> Vec<u8>;
}

pub trait HashAlgorithm {
    fn hash(data: Vec<u8>) -> Vec<u8>;
}

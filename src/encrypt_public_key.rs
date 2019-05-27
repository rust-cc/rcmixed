use crate::traits::{HashAlgorithm, PublicKeyAlgorithm, SymmetricAlgorithm};

pub fn encrypt<T: PublicKeyAlgorithm, S: SymmetricAlgorithm, H: HashAlgorithm>(
    plaintext: Vec<u8>,
    receiver_pk: &T::PublicKey,
    self_sk: &T::SecretKey,
) -> Result<Vec<u8>, ()> {
    Err(())
}

pub fn decrypt<T: PublicKeyAlgorithm, S: SymmetricAlgorithm, H: HashAlgorithm>(
    ciphertext: Vec<u8>,
    sender_pk: &T::PublicKey,
    self_sk: &T::SecretKey,
) -> Result<Vec<u8>, ()> {
    Err(())
}

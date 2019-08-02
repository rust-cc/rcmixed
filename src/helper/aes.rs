use aes_soft::{
    block_cipher_trait::generic_array::GenericArray, block_cipher_trait::BlockCipher, Aes256,
};
use crate::traits::SymmetricAlgorithm;

pub struct AES;

impl SymmetricAlgorithm for AES {
    type Key: Default;
    const KEY_LENGTH: usize = 256 / 8;

    fn encrypt(plain: &[u8], session_key: &Self::Key) -> Vec<u8> {}

    fn decrypt(cipher: &[u8], session_key: &Self::Key) -> Vec<u8> {}

    fn from_bytes(bytes: &[u8]) -> Option<Self::Key> {}

    fn to_bytes(&self) -> Vec<u8> {}
}

use aes_soft::{
    block_cipher_trait::generic_array::GenericArray, block_cipher_trait::BlockCipher, Aes256,
};
use rand::Rng;
use sha3::{Digest, Sha3_256};
use std::ops::Rem;

use crate::traits::{PublicKeyAlgorithm, SignatureAlgorithm};

const SALT_LENGTH: usize = 16;

fn get_kek(
    password: String,
    salt: &[u8],
) -> (GenericArray<u8, <Aes256 as BlockCipher>::KeySize>, Vec<u8>) {
    let mut hasher = Sha3_256::new();

    if salt.len() < SALT_LENGTH {
        let salt = rand::thread_rng().gen::<[u8; SALT_LENGTH]>();
        hasher.input(salt);
        hasher.input(password.as_bytes());
        (hasher.result(), salt.to_vec())
    } else {
        hasher.input(salt);
        hasher.input(password.as_bytes());
        (hasher.result(), salt.to_owned())
    }
}

fn encrypt(
    key: &GenericArray<u8, <Aes256 as BlockCipher>::KeySize>,
    plaintext: &mut Vec<u8>,
    len: usize,
) {
    let cipher = Aes256::new(key);

    let start = len * 16;
    let p_len = plaintext.len() - start;

    let block_len = if p_len > 16 { 16 } else { p_len };
    let mut block = GenericArray::from_mut_slice(&mut plaintext[start..(start + block_len)]);
    cipher.encrypt_block(&mut block);

    if p_len > 16 {
        encrypt(key, plaintext, len + 1);
    }
}

fn decrypt(
    key: &GenericArray<u8, <Aes256 as BlockCipher>::KeySize>,
    ciphertext: &mut [u8],
    len: usize,
) {
    let cipher = Aes256::new(key);

    let start = len * 16;
    let p_len = ciphertext.len() - start;

    let block_len = if p_len > 16 { 16 } else { p_len };
    let mut block = GenericArray::from_mut_slice(&mut ciphertext[start..(start + block_len)]);
    cipher.decrypt_block(&mut block);

    if p_len > 16 {
        decrypt(key, ciphertext, len + 1);
    }
}

pub fn encrypt_secret_key<T: PublicKeyAlgorithm>(sk: &T::SecretKey, password: String) -> Vec<u8> {
    let (kek, mut salt) = get_kek(password, &[]);
    let mut bytes = T::to_bytes(sk);
    let num = bytes.len().rem(16);
    if num != 0 {
        bytes.append(&mut vec![0; 16 - num])
    }

    encrypt(&kek, &mut bytes, 0);
    bytes.append(&mut salt);
    bytes
}

pub fn decrypt_secret_key<T: PublicKeyAlgorithm>(
    mut data: Vec<u8>,
    password: String,
) -> Option<T::SecretKey> {
    let data_len = data.len();
    if data_len < SALT_LENGTH {
        return None;
    }

    let (ciphertext, salt) = data.split_at_mut(data_len - SALT_LENGTH);
    let (kek, _) = get_kek(password, salt);
    decrypt(&kek, ciphertext, 0);
    T::from_bytes(&ciphertext[0..T::SECRET_KEY_LENGTH])
}

pub fn encrypt_sign_key<T: SignatureAlgorithm>(sk: &T::SignKey, password: String) -> Vec<u8> {
    let (kek, mut salt) = get_kek(password, &[]);
    let mut bytes = T::to_bytes(sk);
    let num = bytes.len().rem(16);
    if num != 0 {
        bytes.append(&mut vec![0; 16 - num])
    }

    encrypt(&kek, &mut bytes, 0);
    bytes.append(&mut salt);
    bytes
}

pub fn decrypt_sign_key<T: SignatureAlgorithm>(
    mut data: Vec<u8>,
    password: String,
) -> Option<T::SignKey> {
    let data_len = data.len();
    if data_len < SALT_LENGTH {
        return None;
    }

    let (ciphertext, salt) = data.split_at_mut(data_len - SALT_LENGTH);
    let (kek, _) = get_kek(password, salt);
    decrypt(&kek, ciphertext, 0);
    T::from_bytes(&ciphertext[0..T::SIGN_KEY_LENGTH])
}

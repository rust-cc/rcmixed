use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand::Rng;
use std::io::Cursor;

use crate::traits::{HashAlgorithm, PublicKeyAlgorithm, SignatureAlgorithm, SymmetricAlgorithm};

pub fn encrypt<
    P: PublicKeyAlgorithm,
    S: SymmetricAlgorithm,
    H: HashAlgorithm,
    I: SignatureAlgorithm,
>(
    mut plaintext: Vec<u8>,
    receiver_pk: &P::PublicKey,
    self_sk: &I::SignKey,
) -> Result<Vec<u8>, ()> {
    let mut tmp_data = vec![];

    let mut hash_data = H::hash(&plaintext[..]);
    let mut signature = I::sign(&hash_data, self_sk);
    tmp_data.append(&mut hash_data);
    tmp_data.append(&mut signature);
    tmp_data.append(&mut plaintext);

    // TODO zip plaintext

    let session_bytes: Vec<u8> = (0..S::KEY_LENGTH)
        .map(|_| rand::thread_rng().gen::<u8>())
        .collect();
    let session_key = S::from_bytes(&session_bytes[..]);
    let mut ciphertext = S::encrypt(&tmp_data[..], &session_key);
    let mut cek = P::encrypt(&session_bytes[..], receiver_pk);

    let mut wtr = vec![];
    wtr.write_u32::<BigEndian>(cek.len() as u32).unwrap_or(());

    let mut last_data = vec![];
    last_data.append(&mut wtr);
    last_data.append(&mut cek);
    last_data.append(&mut ciphertext);

    // TODO ASCII radix-64

    Ok(last_data)
}

pub fn decrypt<
    P: PublicKeyAlgorithm,
    S: SymmetricAlgorithm,
    H: HashAlgorithm,
    I: SignatureAlgorithm,
>(
    mut data: Vec<u8>,
    sender_vk: &I::VerifyKey,
    self_sk: &P::SecretKey,
) -> Result<Vec<u8>, ()> {
    // TODO ASCII radix-64

    let (length, cipher) = data.split_at_mut(4);
    let mut rdr = Cursor::new(length);
    let length = rdr.read_u32::<BigEndian>().unwrap_or(0);
    let (cek, ciphertext) = cipher.split_at_mut(length as usize);
    let session_bytes = P::decrypt(cek, self_sk);
    let session_key = S::from_bytes(&session_bytes[..]);
    let mut plaintext = S::decrypt(ciphertext, &session_key);

    // TODO unzip

    let (hash, signature_plaintext) = plaintext.split_at_mut(H::HASH_LENGTH);
    let (signature, plaintext) = signature_plaintext.split_at_mut(I::SIGNATURE_LENGTH);

    if !I::verify(&hash, &signature, sender_vk) || hash != &H::hash(plaintext)[..] {
        return Err(());
    }

    Ok(plaintext.to_vec())
}

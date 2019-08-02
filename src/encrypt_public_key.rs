use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use compress::lz4;
use radix64::STD;
use rand::Rng;
use std::io::{Cursor, Read};

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

    // Use lz4 to zip
    let zip_plaintext = lz4::Encoder::new(tmp_data).finish().0;

    let session_bytes: Vec<u8> = (0..S::KEY_LENGTH)
        .map(|_| rand::thread_rng().gen::<u8>())
        .collect();
    let session_key = S::from_bytes(&session_bytes[..]).unwrap_or(Default::default());
    let mut ciphertext = S::encrypt(&zip_plaintext[..], &session_key);
    let mut cek = P::encrypt(&session_bytes[..], receiver_pk);

    let mut wtr = vec![];
    wtr.write_u32::<BigEndian>(cek.len() as u32).unwrap_or(());

    let mut last_data = vec![];
    last_data.append(&mut wtr);
    last_data.append(&mut cek);
    last_data.append(&mut ciphertext);

    // ASCII radix-64
    let data = STD.encode(&last_data);

    Ok(data.into())
}

pub fn decrypt<
    P: PublicKeyAlgorithm,
    S: SymmetricAlgorithm,
    H: HashAlgorithm,
    I: SignatureAlgorithm,
>(
    rawdata: Vec<u8>,
    sender_vk: &I::VerifyKey,
    self_sk: &P::SecretKey,
) -> Result<Vec<u8>, ()> {
    // ASCII radix-64
    let mut data = STD.decode(&rawdata).unwrap_or(rawdata);

    let (length, cipher) = data.split_at_mut(4);
    let mut rdr = Cursor::new(length);
    let length = rdr.read_u32::<BigEndian>().unwrap_or(0);
    let (cek, ciphertext) = cipher.split_at_mut(length as usize);
    let session_bytes = P::decrypt(cek, self_sk);
    let session_key = S::from_bytes(&session_bytes[..]).unwrap_or(Default::default());
    let zip_plaintext = &S::decrypt(ciphertext, &session_key)[..];

    // use lz4 to unzip
    let mut plaintext = Vec::new();
    if lz4::Decoder::new(zip_plaintext)
        .read_to_end(&mut plaintext)
        .is_err()
    {
        return Err(());
    }

    let (hash, signature_plaintext) = plaintext.split_at_mut(H::HASH_LENGTH);
    let (signature, plaintext) = signature_plaintext.split_at_mut(I::SIGNATURE_LENGTH);

    if !I::verify(&hash, &signature, sender_vk) || hash != &H::hash(plaintext)[..] {
        return Err(());
    }

    Ok(plaintext.to_vec())
}

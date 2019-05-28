mod tmp_trait;

#[cfg(test)]
mod store_tests {
    use rcmixed::store::{
        decrypt_secret_key, decrypt_sign_key, encrypt_secret_key, encrypt_sign_key,
    };
    use rcmixed::traits::{PublicKeyAlgorithm, SignatureAlgorithm};

    use super::tmp_trait::Ed25519;
    use super::tmp_trait::RSA;

    const PASSWORD: &'static str = "thisistest";

    #[test]
    fn sign_test() {
        let sign_key: <Ed25519 as SignatureAlgorithm>::SignKey = [1u8; 32];

        let ciphertext = encrypt_sign_key::<Ed25519>(&sign_key, PASSWORD.to_owned());
        let sign_key_2 = decrypt_sign_key::<Ed25519>(ciphertext, PASSWORD.to_owned());

        assert_eq!(sign_key, sign_key_2.unwrap())
    }

    #[test]
    fn secret_test() {
        let secret_key: <RSA as PublicKeyAlgorithm>::SecretKey = [1u8; 30];

        let ciphertext = encrypt_secret_key::<RSA>(&secret_key, PASSWORD.to_owned());
        let secret_key_2 = decrypt_secret_key::<RSA>(ciphertext, PASSWORD.to_owned());

        assert_eq!(secret_key, secret_key_2.unwrap())
    }
}

trait SignatureAlgorithm {
    type SignKey;
    type VerifyKey;

    fn sign(plain: &Vec<u8>, sign_key: &SignKey) -> Vec<u8>;

    fn verify(plain: &Vec<u8>, sign: &Vec<u8>, verify_key: &VerifyKey) -> bool;
}

trait PublicKeyAlgorithm {
    type PublicKey;
    type PrivateKey;

    fn encrypt(plain: &Vec<u8>, public_key: &PublicKey) -> Vec<u8>;

    fn decrypt(cipher: &Vec<u8>, secret_key: &PrivateKey) -> Vec<u8>;
}

trait SymmetricAlgorithm {
    type Key;

    fn encrypt(plain: &Vec<u8>, session_key: &Key) -> Vec<u8>;

    fn decrypt(cipher: &Vec<u8>, session_key: &Key) -> Vec<u8>;
}

trait HashAlgorithm {
    fn hash(data: Vec<u8>) -> Vec<u8>;
}

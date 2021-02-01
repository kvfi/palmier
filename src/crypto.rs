use openssl::rsa::Rsa;
use openssl::symm::Cipher;

use crate::{io, repo};
use crate::repo::SecureRepository;
use crate::security::hash_password;

pub(crate) fn create_key_pair(s_repo: &mut SecureRepository) {
    let mut passphrase = String::new();
    io::get_input(&mut passphrase, &String::from("Please enter a passphrase to use. It will help generate a keypair:"));

    let rsa = Rsa::generate(1024).unwrap();
    let private_key: Vec<u8> = rsa
        .private_key_to_pem_passphrase(Cipher::aes_128_cbc(), hash_password(&passphrase).as_ref()).unwrap();
    let public_key: Vec<u8> = rsa.public_key_to_pem().unwrap();

    s_repo.keypair = Option::from(repo::KeyPair {
        public: public_key,
        private: private_key,
    });

    match io::write_keypair_fs(&s_repo) {
        Ok(..) => (),
        _ => ()
    }
}
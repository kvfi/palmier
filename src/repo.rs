use std::path::PathBuf;

pub struct SecureRepository {
    pub home_dir: PathBuf,
    pub keypair: Option<KeyPair>,
}

pub struct KeyPair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

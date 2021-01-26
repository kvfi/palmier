use argon2::{self, Config, ThreadMode, Variant, Version};
use openssl::rand::rand_bytes;

pub fn generate_rand_bytes(buf: &mut [u8]) {
    match rand_bytes(buf) {
        Ok(x) => x,
        Err(..) => println!("Cannot create random bytes.")
    }
}

pub fn hash_password(pass: &String) -> String {
    let password = pass.as_bytes();
    let mut salt: [u8; 256] = [0; 256];
    generate_rand_bytes(&mut salt);

    let config = Config {
        variant: Variant::Argon2i,
        version: Version::Version13,
        mem_cost: 65536,
        time_cost: 10,
        lanes: 4,
        thread_mode: ThreadMode::Parallel,
        secret: &[],
        ad: &[],
        hash_length: 32,
    };

    let hash = argon2::hash_encoded(&password, &salt, &config).unwrap();

    hash
}
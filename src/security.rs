use std::{iter, fmt};
use std::str::FromStr;

use argon2::{self, Config, ThreadMode, Variant, Version};
use openssl::rand::rand_bytes;
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;

#[derive(Debug)]
pub(crate) enum StashType {
    TEXT,
    FILE,
}

impl fmt::Display for StashType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for StashType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "TEXT" => Ok(StashType::TEXT),
            "FILE" => Ok(StashType::FILE),
            _ => Err(())
        }
    }
}

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


pub(crate) fn get_rand_string(len: usize) -> String {
    let mut rng = thread_rng();
    let chars: String = iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(len)
        .collect();

    chars
}
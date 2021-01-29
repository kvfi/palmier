use std::{env};
use std::fs::{DirBuilder};
use std::path::Path;
use std::path::PathBuf;
use std::str;

use openssl::rsa::Rsa;
use openssl::symm::Cipher;
use structopt::StructOpt;

use crate::{repo, io};
use crate::repo::{SecureRepository};
use crate::security::hash_password;

#[derive(StructOpt, Debug)]
#[structopt(
name = "Palmier",
about = "Palmier is a secure in-memory, to-disk password storage server with a management system"
)]
enum Cli {
    #[structopt(name = "create", about = "create new crypto repo")]
    Create { name: String },
}

fn handle_opts(cli: Cli) {
    let current_path = env::current_dir().unwrap();

    match cli {
        Cli::Create { name } => {
            let mut paths: Vec<PathBuf> = Vec::new();
            let mut s_rep = repo::SecureRepository {
                home_dir: Path::join(&current_path, &name),
                keypair: None,
            };
            if !Path::exists(&s_rep.home_dir) {
                paths.push(Path::join(&s_rep.home_dir, Path::new(&String::from(".keyvault"))));
                for path in paths {
                    if !Path::exists(&path) {
                        DirBuilder::new()
                            .recursive(true)
                            .create(&path)
                            .unwrap();
                    }
                }
                create_key_pair(&mut s_rep);
            } else {
                println!("Path already exists: {}", s_rep.home_dir.display());
            }
        }
    }
}

fn create_key_pair(s_repo: &mut SecureRepository) {
    let mut passphrase = String::new();
    get_input(&mut passphrase, &String::from("Please enter a passphrase to use. It will help generate a keypair:"));

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

pub fn parse_opts() {
    let cli = Cli::from_args();
    handle_opts(cli);
}

fn get_input(input: &mut String, message: &String) {
    println!("{}", &message);
    std::io::stdin().read_line(input).expect("Failed");
}
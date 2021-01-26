use std::env;
use std::fs::{DirBuilder, File};
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::str;

use openssl::rsa::Rsa;
use openssl::symm::Cipher;
use structopt::StructOpt;

use crate::{repo, security};
use crate::repo::KeyPair;
use crate::security::generate_rand_bytes;

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

                let keypair: KeyPair = create_initial_key_pair();
                s_rep.keypair = Option::from(keypair);

                let mut private_file_name: [u8; 256] = [0; 256];
                generate_rand_bytes(&mut private_file_name);

                let private_file_path: PathBuf = [&s_rep.home_dir, Path::new(&String::from(".keyvault")), Path::new(&String::from_utf8(Vec::from(private_file_name)).unwrap())].iter().collect();
                let mut private_key_f = File::create(private_file_path).unwrap();
                private_key_f.write_all(&s_rep.keypair.unwrap().private);

                println!(
                    "Created new password repository: {}",
                    s_rep.home_dir.display()
                );
                println!("{:?}", name);
            } else {
                println!("Path already exists: {}", s_rep.home_dir.display());
            }
        }
    }
}

fn create_initial_key_pair() -> repo::KeyPair {
    let mut passphrase = String::new();
    get_input(&mut passphrase, &String::from("Please enter a passphrase to use. It will help generate a keypair:"));
    println!("Chosen passphrase: {}", passphrase);
    println!("Test: {}", security::hash_password(&passphrase));

    let rsa = Rsa::generate(1024).unwrap();
    let private_key: Vec<u8> = rsa
        .private_key_to_pem_passphrase(Cipher::aes_128_cbc(), passphrase.as_bytes())
        .unwrap();
    let public_key: Vec<u8> = rsa.public_key_to_pem().unwrap();

    let keypair = repo::KeyPair {
        public: public_key,
        private: private_key,
    };

    keypair
}

pub fn parse_opts() {
    let cli = Cli::from_args();
    handle_opts(cli);
}

fn get_input(input: &mut String, message: &String) {
    println!("{}", &message);
    std::io::stdin().read_line(input).expect("Failed");
}
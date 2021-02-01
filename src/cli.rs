use std::env;
use std::fs::DirBuilder;
use std::path::{Path, PathBuf};
use std::str;

use structopt::StructOpt;

use crate::{crypto, repo, server};
use crate::security::StashType;
use std::str::FromStr;

#[derive(StructOpt, Debug)]
#[structopt(
name = "Palmier",
about = "Palmier is a secure in-memory, to-disk password storage server with a management system"
)]
enum Cli {
    #[structopt(name = "create", about = "create new crypto repo")]
    Create { name: String },
    #[structopt(name = "stash", about = "start Palmier HTTP server")]
    Stash {
        #[structopt(short = "v", long = "value", default_value = "password")]
        value: String
    },
    #[structopt(name = "server", about = "start Palmier HTTP server")]
    Server,
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
                crypto::create_key_pair(&mut s_rep);
            } else {
                println!("Path already exists: {}", s_rep.home_dir.display());
            }
        }
        Cli::Stash { value } => {
            println!("{}", StashType::from_str(&*value).unwrap());
        }
        Cli::Server => {
            server::spin_server();
        }
    }
}

pub fn parse_opts() {
    let cli = Cli::from_args();
    handle_opts(cli);
}

use std::fs::File;
use crate::repo::{SecureRepository};
use crate::security;
use std::path::{Path};
use std::io::Write;

macro_rules! build_from_paths {
    ($base:expr, $($segment:expr),+) => {{
        let mut base: ::std::path::PathBuf = $base.into();
        $(
            base.push($segment);
        )*
        base
    }}
}

pub(crate) fn get_input(input: &mut String, message: &String) {
    println!("{}", &message);
    std::io::stdin().read_line(input).expect("Failed");
}


pub(crate) fn write_keypair_fs(s_repo: &SecureRepository) -> std::io::Result<()> {
    let keypair = s_repo.keypair.as_ref();
    let private_file_name = security::get_rand_string(20);
    let public_key_name = security::get_rand_string(20);

    let mut private_key_file = File::create(build_from_paths!(
        &s_repo.home_dir, Path::new(&String::from(".keyvault")), format!("{}.key", private_file_name)))?;

    let mut public_key_file = File::create(build_from_paths!(
        &s_repo.home_dir, Path::new(&String::from(".keyvault")), format!("{}.asc", public_key_name)))?;

    private_key_file.write_all(&keypair.unwrap().private)?;
    public_key_file.write_all(&keypair.unwrap().public)?;


    Ok(())
}
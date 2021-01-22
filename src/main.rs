use structopt::StructOpt;
use std::path::PathBuf;

#[derive(StructOpt, Debug)]
#[structopt(name = "Palmier", about = "Palmier is a secure in-memory, to-disk password storage server with a management system")]
enum Cli {
    #[structopt(name = "add")]
    Build {
        #[structopt(short = "i")]
        interactive: bool,
        #[structopt(short = "p")]
        patch: bool,
        #[structopt(parse(from_os_str))]
        files: Vec<PathBuf>
    }
}

fn main() {
    let cli = Cli::from_args();
    println!("{:?}", cli);
}

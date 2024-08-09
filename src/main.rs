use std::process;
use clap::Parser;
use merge_sbom::Paths;



fn main(){
    let args: Paths = Paths::parse();

    if let Err(e) = merge_sbom::merge_all(&args) {
        eprintln!("Application error: {e}");
        process::exit(1);
    }
}
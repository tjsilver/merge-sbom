use std::env;
use std::process;

use merge_sbom::Config;

fn main() {
    let args: Vec<String> = env::args().collect();

    let config = Config::build(&args).unwrap_or_else(|err|{
        println!("Problem parsing arguments: {err}");
        process::exit(1);
    });

    println!("Merging {} and {}", config.path1, config.path2);

    if let Err(e) = merge_sbom::run(config) {
        println!("Application error: {e}");
        process::exit(1);
    }


}

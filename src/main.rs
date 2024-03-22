use std::env;
use std::process;

use merge_sbom::Config;


fn main() {
    let args: Vec<String> = env::args().collect();

    let config = Config::build(&args).unwrap_or_else(|err|{
        eprintln!("Problem parsing arguments: {err}");
        process::exit(1);
    });

    eprintln!("Merging {} and {}", config.path1, config.path2);

    // if let Err(e) = merge_sbom::merge(config) {
    //     eprintln!("Application error: {e}");
    //     process::exit(1);
    // }
    if let Err(e) = merge_sbom::read_to_type(config) {
        eprintln!("Application error: {e}");
        process::exit(1);
    }


}
// json structure  - use serde_json
// try to merge & dedupe e.g. person

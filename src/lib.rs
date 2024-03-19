
use std::error::Error;
use std::fs::OpenOptions;
use std::fs::File;
use std::path::Path;
use std::io::{self, BufRead, Write};

pub struct Config {
    pub path1: String,
    pub path2: String,
}

impl Config {
    pub fn build(args: &[String]) -> Result<Config, &'static str> {
        if args.len() < 3 {
            return Err("Not enough arguments");
        }

        let path1 = args[1].clone();
        let path2 = args[2].clone();

        Ok(Config { path1, path2 })
    }
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {

    // let mut file1 = OpenOptions::new()
    // .append(true)
    // .open(config.path1)
    // .expect("Cannot open first file");

    // let file2 = OpenOptions::new()
    // .read(true)
    // .open(config.path2)
    // .expect("Cannot open second file");

    if let Ok(lines) = read_lines(config.path2) {
        for line in lines.flatten() {
            println!("{}", line);
        }
    }

    Ok(())
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
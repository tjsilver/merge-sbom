
#![allow(non_snake_case)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use std::collections::HashSet;
use std::fs::{self, File};
use std::path::Path;
use std::io::{self, BufRead};

pub struct Config {
    pub path1: String,
    pub path2: String,
}

#[derive(Serialize, Deserialize)]
struct CreationInfo {
    created: DateTime<Utc>,
    creators: HashSet<String>, 
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash)]
struct ExternalRef {
    referenceCategory: String,
    referenceType: String,
    referenceLocator: String, 
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash)]
struct Package {
    SPDXID: String,
    name: String,
    versionInfo: String,
    downloadLocation: String,
    filesAnalyzed: bool,
    supplier: String,
    externalRefs: Vec<ExternalRef>
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash)]
struct Relationship {
    relationshipType: String,
    spdxElementId: String,
    relatedSpdxElement: String,
}
#[derive(Serialize, Deserialize)]
struct Sbom {
    SPDXID: String,
    spdxVersion: String,
    creationInfo: CreationInfo,
    name: String,
    dataLicense: String,
    documentDescribes: Vec<String>,
    documentNamespace: String,
    packages: HashSet<Package>,
    relationships: HashSet<Relationship>

}

impl Config {
    pub fn build(args: &[String]) -> std::result::Result<Config, &'static str> {
        if args.len() < 3 {
            return Err("Not enough arguments");
        }

        let path1 = args[1].clone();
        let path2 = args[2].clone();

        Ok(Config { path1, path2 })
    }
}
pub fn read_to_type(config: Config) -> anyhow::Result<()> {
   
    let data = fs::read_to_string(config.path1)?;

    let sbom_json: Sbom = serde_json::from_str(&data)?;
    println!("Sbom name: {}", sbom_json.name);
    println!("SPDXID: {}", sbom_json.SPDXID);
    println!("spdxVersion: {}", sbom_json.spdxVersion);

    for package in &sbom_json.packages {
        println!("package name: {}", package.name);
        println!("version: {}", package.versionInfo);
    }
    

    Ok(())
}

// pub fn merge(config: Config) -> std::result::Result<(), Box<dyn Error>> {


//     if let Ok(lines) = read_lines(config.path1) {
//         for line in lines.flatten() {
//             println!("{}", line);
//         }
//     }

//     if let Ok(lines) = read_lines(config.path2) {
//         for line in lines.flatten() {
//             println!("{}", line);
//         }
//     }

//     Ok(())
// }

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

// TODO:
// SPDXID: String, - dedupe

// spdxVersion: String, - assert versions match vSPDX-2.3 & dedupe

// struct CreationInfo {
//     created: String, - new Date (now) Chrono
//     creators: HashSet<String>,  - dedupe (hashset) & add toolname as creator
// }

// name: String,
// dataLicense: String,
// documentDescribes: Vec<String>,
// documentNamespace: String,
// packages: Vec<Package>, - dedupe, maybe keep order
// relationships: Vec<Relationship> - dedupe 
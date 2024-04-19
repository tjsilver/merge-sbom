#![allow(non_snake_case)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::hash::Hash;
use std::fs;
use anyhow::Result;

pub struct Config {
    pub path1: String,
    pub path2: String,
}

#[derive(Serialize, Deserialize)]
struct CreationInfo {
    created: DateTime<Utc>,
    creators: HashSet<String>, 
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
struct ExternalRef {
    referenceCategory: String,
    referenceType: String,
    referenceLocator: String, 
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
struct Package {
    SPDXID: String,
    name: String,
    versionInfo: String,
    downloadLocation: String,
    filesAnalyzed: bool,
    supplier: String,
    externalRefs: Option<Vec<ExternalRef>>
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
    pub fn build(args: &[String]) -> Result<Config, &'static str> {
        if args.len() < 3 {
            return Err("Not enough arguments");
        }

        let path1 = args[1].clone();
        let path2 = args[2].clone();

        Ok(Config { path1, path2 })
    }
}

fn json_to_sbom(filepath: String) -> Result<Sbom> {
   
    let json = fs::read_to_string(&filepath)?;

    let sbom: Sbom = serde_json::from_str(&json)?;

    eprintln!("Sbom name: {}", &sbom.name);
    eprintln!("SPDXID: {}", &sbom.SPDXID);
    eprintln!("spdxVersion: {}", &sbom.spdxVersion);
    
    Ok(sbom)
}

fn sbom_to_string(sbom: Sbom) -> Result<String> {

    let merged = serde_json::to_string_pretty(&sbom)?;

    Ok(merged)
}

fn merge_hashsets<T>(hash1: HashSet<T>, hash2: HashSet<T>) -> Result<HashSet<T>> 
where
    T: Clone + Eq + Hash, {
        eprintln!("hash1 has length: {}", hash1.len());
        eprintln!("hash2 has length: {}", hash2.len());
    
        let mut merged_hashset = hash1;
        merged_hashset.extend(hash2);

        eprintln!("merged_hashset has length: {}", merged_hashset.len());

        Ok(merged_hashset.clone())
    }

fn merge(sbom1: Sbom, sbom2:Sbom) -> Result<Sbom> {

    let creators_joined = merge_hashsets(sbom1.creationInfo.creators, sbom2.creationInfo.creators);
    let packages_joined = merge_hashsets(sbom1.packages, sbom2.packages);
    
    let merged: Sbom = Sbom { 
        SPDXID: sbom1.SPDXID, 
        spdxVersion: sbom1.spdxVersion, 
        creationInfo: CreationInfo {
            created: Utc::now(),
            creators: creators_joined?, 
        }, 
        name: sbom1.name, 
        dataLicense: String::from("Test data license"), 
        documentDescribes: [String::from("Test document describes")].to_vec(), 
        documentNamespace: String::from("Test document namespace"), 
        packages: packages_joined?, 
        relationships: sbom1.relationships 
    };


    Ok(merged)    
}

pub fn merge_all(config: Config) -> Result<()>{

    let path1 = config.path1;
    let path2 = config.path2;

    eprintln!("Merging {} and {}.", &path1, &path2);

    let sbom1 = json_to_sbom(path1).unwrap();
    let sbom2 = json_to_sbom(path2).unwrap();

    let sbom_final = merge(sbom1, sbom2);

    let merged = sbom_to_string(sbom_final?).unwrap();

    println!("{}", merged);

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
    #[test]
    fn merge_hashsets_works() {
        let mut hash1 = HashSet::new();

        hash1.insert("To Kill a Mockingbird".to_string());
        hash1.insert("The Odyssey".to_string());
        hash1.insert("The Great Gatsby".to_string());

        let mut hash2 = HashSet::new();
        hash2.insert("To Kill a Mockingbird".to_string());
        hash2.insert("The Odyssey".to_string());
        hash2.insert("A Dance With Dragons".to_string());

        let mut expected = HashSet::new();
        expected.insert("To Kill a Mockingbird".to_string());
        expected.insert("The Odyssey".to_string());
        expected.insert("The Great Gatsby".to_string());
        expected.insert("A Dance With Dragons".to_string());


        assert_eq!(expected, merge_hashsets(hash1, hash2));
    }
}

// TODO:
// Add test(s) to ensure that the serialization & deserialization result is identical to original json

// Merging: 
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
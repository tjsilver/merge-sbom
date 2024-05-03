#![allow(non_snake_case)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::hash::Hash;
use std::fs;
use anyhow::{bail, Result};

pub struct Config {
    pub path1: String,
    pub path2: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct CreationInfo {
    licenseListVersion: Option<String>,
    created: DateTime<Utc>,
    creators: HashSet<String>, 
    comment: Option<String>,
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
pub struct Sbom {
    SPDXID: String,
    spdxVersion: String,
    creationInfo: CreationInfo,
    name: String,
    dataLicense: String,
    documentDescribes: Option<HashSet<String>>,
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

fn combine_options<T, A>(a: Option<T<A>>, b: Option<T<A>>, func: impl Fn(T<A>) -> T<A>) -> T<A> {
    //TODO - make a generic function that checks if there are Somes in each and runs the function passed in.
}

fn merge_hashsets<T>(hash1: HashSet<T>, hash2: HashSet<T>) -> HashSet<T> 
where
    T: Clone + Eq + Hash, {
        eprintln!("hashset1 has length: {}", hash1.len());
        eprintln!("hashset2 has length: {}", hash2.len());
    
        let mut merged_hashset = hash1;
        merged_hashset.extend(hash2);

        eprintln!("merged_hashset has length: {}", merged_hashset.len());

        merged_hashset
    }

fn merge_option_hashsets<T>(d1: Option<HashSet<T>>, d2: Option<HashSet<T>>) -> Option<HashSet<T>> 
where
    T: Clone + Eq + Hash, {
    if d1.is_some() && d2.is_some() {
        return Some(merge_hashsets(d1.unwrap(), d2.unwrap()));
    }
    else if d1.is_some() {
        return d1;
    }
    else if d2.is_some() {
        return d2;
    }
    return None;
}

fn combine_strings(s1:String, s2:String) -> String {
    if s1 == s2 {
        return s1;
    }
    format!("{} AND {}", s1, s2)
}

fn combine_option_strings(c1: Option<String>, c2: Option<String>) -> Option<String> {
    if c1.is_some() && c2.is_some() {
        return Some(combine_strings(c1.unwrap(), c2.unwrap()));
    }
    else if c1.is_some() {
        return c1;
    }
    else if c2.is_some() {
        return c2;
    }
    return None;
}

fn merge(sbom1: Sbom, sbom2:Sbom) -> Result<Sbom> {

    const VERSION: &str = "SPDX-2.3";
    if sbom1.spdxVersion != VERSION || sbom2.spdxVersion != VERSION {
        bail!("Version mismatch: SPDX version in both files must be {}", VERSION);
    }

    let mut all_creators = merge_hashsets(sbom1.creationInfo.creators, sbom2.creationInfo.creators);
    all_creators.insert(String::from("Tool: Guardian.com-Merge-SBOM"));
    
    let merged: Sbom = Sbom { 
        SPDXID: sbom1.SPDXID, 
        spdxVersion: sbom1.spdxVersion, 
        creationInfo: CreationInfo {
            licenseListVersion: combine_option_strings(sbom1.creationInfo.licenseListVersion, sbom2.creationInfo.licenseListVersion),
            created: Utc::now(),
            creators: all_creators, 
            comment: combine_option_strings(sbom1.creationInfo.comment, sbom2.creationInfo.comment)
        }, 
        name: format!("{} AND {}", sbom1.name, sbom2.name), 
        dataLicense: combine_strings(sbom1.dataLicense, sbom2.dataLicense), 
        documentDescribes: merge_option_hashsets(sbom1.documentDescribes, sbom2.documentDescribes),
        documentNamespace: String::from("Test document namespace"), 
        packages: merge_hashsets(sbom1.packages, sbom2.packages),
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

    // #[test]
    // fn test_test() {
    //     let good = serde_json::from_str::<Sbom>(EXAMPLE);
    // }
}

// TODO:
// tests - multi-line strings or .json file
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
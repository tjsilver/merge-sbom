use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::hash::Hash;
use std::fs;
use anyhow::{bail, Result};

pub struct Config {
    pub path1: String,
    pub path2: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]	

pub struct Sbom {
    #[serde(rename = "SPDXID")]
    pub spdxid: String,
    pub spdx_version: String,
    pub data_license: String,
    pub creation_info: CreationInfo,
    pub document_namespace: String,
    pub name: String,
    pub packages: HashSet<Package>,
    pub relationships: HashSet<Relationship>,
    pub comment: Option<String>,
    pub external_document_refs: Option<HashSet<ExternalDocumentRef>>,
    pub has_extracted_licensing_infos: Option<HashSet<HasExtractedLicensingInfo>>,
    pub annotations: Option<HashSet<Annotation>>,
    pub document_describes: Option<HashSet<String>>,
    pub files: Option<HashSet<File>>,
    pub snippets: Option<HashSet<Snippet>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreationInfo {
    #[serde(default)]
    pub created: DateTime<Utc>,
    #[serde(default)]
    pub creators: HashSet<String>,
    pub comment: Option<String>,    
    pub license_list_version: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct ExternalDocumentRef {
    #[serde(default)]
    pub external_document_id: String,
    #[serde(default)]
    pub checksum: Checksum,
    #[serde(default)]
    pub spdx_document: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct Checksum {
    #[serde(default)]
    pub algorithm: String,
    #[serde(default)]
    pub checksum_value: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct HasExtractedLicensingInfo {
    #[serde(default)]
    pub license_id: String,
    #[serde(default)]
    pub extracted_text: String,
    pub comment: Option<String>,
    pub name: Option<String>,
    #[serde(default)]
    pub see_alsos: Option<Vec<String>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct Annotation {
    #[serde(default)]
    pub annotation_date: DateTime<Utc>,
    #[serde(default)]
    pub annotation_type: String,
    pub annotator: Option<String>,
    pub comment: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct Package {
    #[serde(rename = "SPDXID")]
    pub spdxid: String,
    #[serde(default)]
    pub supplier: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version_info: String,
    #[serde(default)]
    pub annotations: BTreeSet<Annotation>,
    #[serde(default)]
    pub attribution_texts: Vec<String>,
    pub built_date: Option<String>,
    #[serde(default)]
    pub checksums: BTreeSet<Checksum>,
    #[serde(default)]
    pub download_location: String,
    #[serde(default)]
    pub external_refs: BTreeSet<ExternalRef>,    
    #[serde(default)]
    pub files_analyzed: bool,
    #[serde(default)]
    pub has_files: BTreeSet<String>,
    pub copyright_text: Option<String>,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub license_comments: Option<String>,
    pub license_concluded: Option<String>,
    pub license_declared: Option<String>,
    pub license_info_from_files: Option<BTreeSet<String>>,
    pub originator: Option<String>,
    pub package_file_name: Option<String>,
    pub package_verification_code: Option<PackageVerificationCode>,
    pub primary_package_purpose: Option<String>,
    pub release_date: Option<String>,
    pub source_info: Option<String>,
    pub summary: Option<String>,
    pub valid_until_date: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ExternalRef {    
    #[serde(default)]
    pub reference_category: String,
    #[serde(default)]
    pub reference_locator: String,
    #[serde(default)]
    pub reference_type: String,
    pub comment: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct PackageVerificationCode {
    #[serde(default)]
    pub package_verification_code_value: String,
    pub package_verification_code_excluded_files: Option<Vec<String>>,    
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct File {
    #[serde(rename = "SPDXID")]
    pub spdxid: String,
    #[serde(default)]
    pub checksums: Vec<Checksum>,
    #[serde(default)]
    pub file_contributors: BTreeSet<String>,
    #[serde(default)]
    pub file_name: String,
    pub copyright_text: Option<String>,
    pub file_types: Option<BTreeSet<String>>,
    pub license_concluded: Option<String>,
    pub license_info_in_files: Option<BTreeSet<String>>,
    pub comment: Option<String>,
    pub notice_text: Option<String>,
    pub license_comments: Option<String>,
    pub annotations: Option<Vec<Annotation>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Snippet {
    #[serde(rename = "SPDXID")]
    pub spdxid: String,   
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub copyright_text: String,
    #[serde(default)]
    pub license_comments: String,
    #[serde(default)]
    pub license_concluded: String,
    #[serde(default)]
    pub license_info_in_snippets: BTreeSet<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub ranges: Vec<Range>,
    #[serde(default)]
    pub snippet_from_file: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Range {
    #[serde(default)]
    pub end_pointer: EndPointer,
    #[serde(default)]
    pub start_pointer: StartPointer,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct EndPointer {
    #[serde(default)]
    pub reference: String,
    pub offset: Option<i64>,
    pub line_number: Option<i64>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct StartPointer {
    #[serde(default)]
    pub reference: String,
    pub offset: Option<i64>,
    pub line_number: Option<i64>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Relationship {
    #[serde(default)]
    pub spdx_element_id: String,
    #[serde(default)]
    pub relationship_type: String,
    #[serde(default)]
    pub related_spdx_element: String,
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

pub fn json_to_sbom(filepath: String) -> Result<Sbom> {
   
    let json = fs::read_to_string(filepath).unwrap();

    let sbom: Sbom = serde_json::from_str(&json)?;
    eprintln!("Sbom name: {}", &sbom.name);
    eprintln!("SPDXID: {}", &sbom.spdxid);
    eprintln!("spdxVersion: {}", &sbom.spdx_version);
    
    Ok(sbom)
}

pub fn sbom_to_string(sbom: Sbom) -> Result<String> {

    let merged = serde_json::to_string_pretty(&sbom)?;

    Ok(merged)
}

// fn combine_options<T, A>(a: Option<T<A>>, b: Option<T<A>>, func: impl Fn(T<A>) -> T<A>) -> T<A> {
//     //TODO - make a generic function that checks if there are Somes in each and runs the function passed in.
// }

fn merge_hashsets<T>(hash1: HashSet<T>, hash2: HashSet<T>) -> HashSet<T> 
where
    T: Clone + Eq + Hash, {
        let mut merged_hashset = hash1;
        merged_hashset.extend(hash2);

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
    None
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
    None
}

fn merge(sbom1: Sbom, sbom2:Sbom) -> Result<Sbom> {
    const VERSION: &str = "SPDX-2.3";
    if sbom1.spdx_version != VERSION || sbom2.spdx_version != VERSION {
        bail!("Version mismatch: SPDX version in both files must be {}", VERSION);
    } else {
        eprintln!("SPDX version is {}", VERSION);
    }

    let mut all_creators = merge_hashsets(sbom1.creation_info.creators, sbom2.creation_info.creators);
    all_creators.insert(String::from("Tool: Guardian.com-Merge-SBOM"));

    
    let merged: Sbom = Sbom { 
        spdxid: sbom1.spdxid, 
        spdx_version: sbom1.spdx_version, 
        creation_info: CreationInfo {
            license_list_version: combine_option_strings(sbom1.creation_info.license_list_version, sbom2.creation_info.license_list_version),
            created: Utc::now(),
            creators: all_creators, 
            comment: combine_option_strings(sbom1.creation_info.comment, sbom2.creation_info.comment)
        }, 
        name: format!("{} AND {}", sbom1.name, sbom2.name), 
        data_license: combine_strings(sbom1.data_license, sbom2.data_license), 
        document_describes: merge_option_hashsets(sbom1.document_describes, sbom2.document_describes),
        document_namespace: combine_strings(sbom1.document_namespace, sbom2.document_namespace), 
        packages: merge_hashsets(sbom1.packages, sbom2.packages),
        relationships: merge_hashsets(sbom1.relationships, sbom2.relationships),
        comment: combine_option_strings(sbom1.comment, sbom2.comment),
        external_document_refs: merge_option_hashsets(sbom1.external_document_refs, sbom2.external_document_refs),
        has_extracted_licensing_infos: merge_option_hashsets(sbom1.has_extracted_licensing_infos, sbom2.has_extracted_licensing_infos),
        annotations: merge_option_hashsets(sbom1.annotations, sbom2.annotations),
        files: merge_option_hashsets(sbom1.files, sbom2.files),
        snippets: merge_option_hashsets(sbom1.snippets, sbom2.snippets), 
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
        hash2.insert("A Dance With Dragons".to_string());

        let mut expected = HashSet::new();
        expected.insert("To Kill a Mockingbird".to_string());
        expected.insert("The Odyssey".to_string());
        expected.insert("The Great Gatsby".to_string());
        expected.insert("A Dance With Dragons".to_string());


        assert_eq!(expected, merge_hashsets(hash1, hash2));
    }

    #[test]
    fn  merge_option_hashsets_works() {
        let mut hash1 = HashSet::new();

        hash1.insert("To Kill a Mockingbird".to_string());
        hash1.insert("The Odyssey".to_string());
        hash1.insert("The Great Gatsby".to_string());

        let hash1_option = Some(hash1.clone());

        let mut hash2 = HashSet::new();
        hash2.insert("To Kill a Mockingbird".to_string());
        hash2.insert("A Dance With Dragons".to_string());

        let hash2_option = Some(hash2.clone());

        let mut expected = HashSet::new();
        expected.insert("To Kill a Mockingbird".to_string());
        expected.insert("The Odyssey".to_string());
        expected.insert("The Great Gatsby".to_string());
        expected.insert("A Dance With Dragons".to_string());

        let expected_option = Some(expected.clone());

        assert_eq!(expected_option, merge_option_hashsets(hash1_option, hash2_option));

    }

    #[test]
    fn  merge_option_hashsets_works_with_none() {
        let mut hash1 = HashSet::new();

        hash1.insert("To Kill a Mockingbird".to_string());
        hash1.insert("The Odyssey".to_string());
        hash1.insert("The Great Gatsby".to_string());

        let hash1_option = Some(hash1.clone());

        let hash2_option = None;

        let mut expected = HashSet::new();
        expected.insert("To Kill a Mockingbird".to_string());
        expected.insert("The Odyssey".to_string());
        expected.insert("The Great Gatsby".to_string());

        let expected_option = Some(expected.clone());

        assert_eq!(expected_option, merge_option_hashsets(hash1_option, hash2_option));

    }

    #[test]

    fn  merge_option_hashsets_works_with_two_nones() {

        let hash1_option: Option<HashSet<String>> = None;

        let hash2_option: Option<HashSet<String>> = None;

        let expected_option: Option<HashSet<String>> = None;

        assert_eq!(expected_option, merge_option_hashsets(hash1_option, hash2_option));

    }

    #[test]
    fn combine_option_strings_works() {
        let string1_option = Some(String::from("First string"));
        let string2_option = Some(String::from("Second string"));
        let expected = Some(String::from("First string AND Second string"));
        assert_eq!(expected, combine_option_strings(string1_option, string2_option));
    }

    #[test]
    fn combine_option_strings_works_empty_string() {
        let string1_option: Option<String> = None;
        let string2_option = Some(String::from("Second string"));
        let expected = Some(String::from("Second string"));
        assert_eq!(expected, combine_option_strings(string1_option, string2_option));
    }
}

// TODO:
// tests - multi-line strings or .json file
// Add test(s) to ensure that the serialization & deserialization result is identical to original json


/*  NTIA Minimum Elements and SPDX 2.3 mandatory fields
(see https://spdx.github.io/spdx-ntia-sbom-howto/#_3_5_summary_of_required_fields)
Package.supplier x
Package.name x
Package.versionInfo x
DocumentNamespace x
SPDXID x
Relationship (CONTAINS)
Creator
Created
SPDXVersion
DataLicense
SPDXID (for Document)
DocumentName	
PackageDownloadLocation	
FilesAnalyzed
Relationship (DESCRIBES, for primary Package)
*/